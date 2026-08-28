"use strict";
/*
 * PolicyVault dashboard (current protocol: v0.4.1).
 *
 * Normal, human-facing product experience over the tested, server-authoritative
 * v0.4.1 endpoints (/api/v1/wallet/v4/*). The BROWSER IS UNTRUSTED: this layer
 * only collects friendly inputs (wallet addresses, KAS amounts, a budget-reset
 * period) and shows canonical reviews — the server independently derives and
 * validates every consensus-visible value (address→x-only, KAS→sompi, node DAA,
 * periodSpent=0). Owner/agent/approver signing all use the wallet's signPskt
 * over the frozen transaction, then broadcast to the server's configured
 * network (state.serverNetwork — testnet-10 or mainnet; never assumed).
 */
(function () {
  const API = "/api/v1";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const short = (id) => (id ? id.slice(0, 8) + "…" + id.slice(-6) : "—");
  const randomHex32 = () => Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("");

  /* In-app contextual help (owner's docs addendum §8): a small link out to
   * the live docs site, https://docs.policy-vault.org — small contextual
   * explanations stay in the product; the deeper walkthrough lives in the
   * docs. Always opens a new tab (never navigates away from an in-progress
   * form/session) and never leaks a referrer. Slugs are verified against
   * the live docs build, never guessed — see docs/postlaunch/ (TRACK B
   * phase 7 report) for the verification list. Static text only: never
   * pass anything user- or server-supplied through this (title text is a
   * plain browser tooltip, not HTML, so it needs no separate escaping,
   * but every string passed in here is a literal in THIS file). */
  const DOCS_BASE = "https://docs.policy-vault.org";
  const docsLink = (slug, label) => `<a href="${DOCS_BASE}/${slug}/" target="_blank" rel="noopener noreferrer">${label || "Learn more"}</a>`;
  const docsHintIcon = (slug, title) => ` <a class="hint docs-hint" href="${DOCS_BASE}/${slug}/" target="_blank" rel="noopener noreferrer" title="${esc(title)}" aria-label="${esc(title)}">ⓘ</a>`;

  // No independent wallet state: the v0.4.1 app consumes the ONE canonical
  // browser wallet session (window.PolicyVaultWalletSession, owned by the global
  // Wallet panel). It never opens a second provider connection.
  const state = { address: null, xonly: null, network: null, serverNetwork: null, ready: false, provider: null, view: "vaults", statusFilter: "Active", org: "all", renderedOnce: false, orgData: null, openReqs: [], vaultsById: {} };
  const session = () => (window.PolicyVaultWalletSession ? window.PolicyVaultWalletSession.active() : { connected: false, ready: false });
  // Server-derived network display label (never a hardcoded network name):
  // state.serverNetwork is set from GET /health at DOMContentLoaded (below)
  // and is the ONLY source of truth for what network this build talks to.
  // Falls back to a neutral phrase before that resolves — never guesses
  // "testnet-10". Display-only; every real network check stays on the
  // session gate (state.ready) and the server.
  const networkLabel = () => state.serverNetwork || "the configured network";

  /* ---- BROWSER-LOCAL PRE-SIGN VERIFICATION (PostLaunchUpgradeOG) ----
   * web/verify-intent.js + web/core-bundle.js run the portable shared-core
   * intent-manifest verifier IN THE BROWSER over the EXACT unsigned Safe
   * JSON about to be signed, against the user's OWN action context and the
   * vault state this browser already knows. When the module is loaded
   * (production index.html always loads it) verification is MANDATORY:
   * any refusal — or a missing/unbound verification — BLOCKS the wallet
   * prompt (walletSign stage D2). A page served without the module is a
   * legacy build: the signing modal then carries a visible warning that
   * independent verification is unavailable. */
  const verifyGate = () => (window.PolicyVaultVerifyIntent && typeof window.PolicyVaultVerifyIntent.verifyBeforeSigning === "function" ? window.PolicyVaultVerifyIntent : null);
  function verifyForSigning({ request, vaultId, clientAction, clientParams, clientFuel, role, createContext }) {
    const gate = verifyGate();
    if (!gate) return null; // legacy build — visibly labeled in the modal
    const s = session();
    return gate.verifyBeforeSigning({
      request,
      vault: vaultId !== undefined ? state.vaultsById[vaultId] : undefined,
      createContext,
      clientAction,
      clientParams,
      clientFuel,
      sessionNetwork: s.network,
      sessionXOnly: state.xonly,
      role
    });
  }

  /* Hosted/API errors arrive as { error: { code, message } } (self-hosted
   * legacy routes may use a bare string). Extract message AND code exactly
   * like app.js — the Phase G human run hit a session-expiry 401 here and
   * the vaults view rendered "[object Object]" because the raw envelope
   * object was passed to new Error(). Callers rely on e.code (e.g.
   * ORG_NOT_EMPTY, AUTH_*) and e.message; e.payload keeps the full body. */
  function apiError(j, r) {
    return Object.assign(new Error((j.error && j.error.message) || j.error || r.statusText), {
      code: (j.error && j.error.code) || j.code,
      payload: j
    });
  }
  async function getJSON(p) {
    const r = await fetch(API + p);
    const j = await r.json();
    if (!r.ok) throw apiError(j, r);
    return j;
  }
  async function postJSON(p, body) {
    const r = await fetch(API + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok) throw apiError(j, r);
    return j;
  }
  async function resolveXOnly(address) {
    const { identity } = await postJSON("/identity/resolve-address", { address });
    return identity.xOnlyPubkey;
  }
  function note(msg, cls) {
    const el = $("v4-notice");
    if (!el) return;
    el.textContent = msg;
    el.className = "panel " + (cls || "");
    el.style.display = msg ? "block" : "none";
  }

  /* ---- Governance ceremony / risk hold / org-controls UI modules ----
   * (PostLaunchUpgradeOG completion-standard items 1/2/3/6). Each is a
   * separate web/*.js module (never touching web/verify-intent.js or
   * web/core-bundle.js) constructed fresh per call from the SAME
   * getJSON/postJSON this file already uses — no separate network layer,
   * no separate signing path. A page served without one of these modules
   * degrades to the pre-existing plain refusal note() (checked at every
   * call site below) rather than crashing. */
  const govUI = () => (window.PolicyVaultGovernanceUI ? window.PolicyVaultGovernanceUI.createModule({ api: { getJSON, postJSON } }) : null);
  const riskUI = () => (window.PolicyVaultRiskUI ? window.PolicyVaultRiskUI.createModule({ api: { getJSON, postJSON } }) : null);
  const orgControlsUI = () => (window.PolicyVaultOrgControlsUI ? window.PolicyVaultOrgControlsUI.createModule({ api: { getJSON, postJSON, resolveXOnly } }) : null);

  /* Owner ops are fuel-funded; auto-select the owner's largest ordinary
   * UTXO from the server. Module-scope (not just wireVault-local) so a
   * governance-ceremony RETRY reached from the persistent open-proposals
   * list (which has no live form params in hand — only the proposal's own
   * stored action/params, which never carry `fuel`; server/src/
   * governance.js stripExecutionOnlyParams excludes it by design) can
   * re-select fresh fuel exactly like the original action did, instead of
   * silently retrying with a missing/stale UTXO reference. */
  const withFuel = async (params, minSompi = "200000000") => {
    try {
      const { utxos } = await getJSON(`/wallet/fuel/${encodeURIComponent(state.address)}`);
      const u = (utxos || []).find((x) => BigInt(x.amount) > BigInt(minSompi));
      if (!u) { note(`No ordinary UTXO > ${(Number(minSompi) / 1e8)} KAS at ${short(state.address)} — fund the owner address first.`, "bad"); return null; }
      return { ...params, fuel: { outpoint: u.outpoint, amount: u.amount, scriptPublicKeyHex: u.scriptPublicKeyHex } };
    } catch (e) { note(`Could not fetch fuel: ${e.message}`, "bad"); return null; }
  };

  /* React to the ONE canonical wallet session. Account/network changes are
   * SECURITY EVENTS: re-derive the active identity, discard any in-progress
   * signing modal, and re-render (which re-runs role derivation + disables
   * actions when the wallet is not on the server's configured network). */
  async function updateWallet(snap) {
    const changed = snap.address !== state.address || snap.network !== state.network || snap.ready !== state.ready;
    const hadXOnly = !!state.xonly;
    state.address = snap.ready ? snap.address : (snap.address || null);
    state.network = snap.network;
    state.ready = snap.ready;
    state.provider = snap.provider;
    state.xonly = snap.xonly || null;
    // If the session hasn't resolved x-only yet but is ready, resolve it once.
    if (snap.ready && snap.address && !state.xonly) {
      try { state.xonly = await resolveXOnly(snap.address); } catch { state.xonly = null; }
    }
    const box = $("v4-wallet");
    if (box) {
      if (!snap.connected) box.innerHTML = `No wallet connected. <b>Connect KasWare in the Wallet panel above to continue.</b>`;
      else if (!snap.ready) box.innerHTML = `Wallet is on <b>${esc(snap.network || "unknown")}</b> — PolicyVault is configured for <b>${esc(networkLabel())}</b>. Switch KasWare to ${esc(networkLabel())} to sign.`;
      else box.innerHTML = `Signing wallet <span class="mono">${esc(snap.address)}</span> · network <b>${esc(snap.network)}</b> · <span class="badge ver">${esc(snap.provider || "wallet")}</span> · <span class="hint" style="display:inline">role is derived per vault below</span>`;
    }
    if (changed) {
      const m = $("v4-modal");
      if (m && m.style.display === "flex") { m.style.display = "none"; note("Wallet changed — the in-progress action was discarded. Rebuild it under the current wallet.", "warn"); }
    }
    // Re-render ONLY when something rendered actually changed (wallet identity/
    // network/readiness, a newly resolved x-only role key, or first paint).
    // Re-rendering on every identical session snapshot both wiped in-progress
    // form input and — before the one-time delegated wiring below — accumulated
    // duplicate listeners (the H2 approver-row multiplication bug).
    const xonlyChanged = !!state.xonly !== hadXOnly;
    if (changed || xonlyChanged || !state.renderedOnce) render();
  }

  /* Every signing request must carry the CANONICAL FROZEN metadata committed
   * in the durable request: an integer input index and an explicit
   * sighashType 1 (SIG_HASH_ALL — the only type this application ever emits).
   * The browser never invents or trims signing semantics. Real-KasWare
   * incident (request 98190595): a reconstructed entry without sighashType
   * became sighashTypes:[undefined] inside KasWare's signPskt, coerced to the
   * invalid sighash type 0 via new Uint8Array([undefined]), and panicked
   * kaspa-wasm with "unreachable" AFTER the human clicked Sign. This guard
   * fails closed BEFORE any wallet popup can be opened with bad metadata. */
  function assertCanonicalSignInputs(list) {
    if (!Array.isArray(list) || list.length === 0) {
      throw Object.assign(new Error("signing metadata missing — refusing to invoke the wallet"), { code: "SIGN_INPUTS_INVALID" });
    }
    for (const si of list) {
      if (!si || !Number.isInteger(si.index) || si.index < 0 || si.sighashType !== 1) {
        throw Object.assign(new Error(`signing entry ${JSON.stringify(si)} is not the canonical frozen { index, sighashType: 1 } — refusing to invoke the wallet`), { code: "SIGN_INPUTS_INVALID" });
      }
    }
  }

  /* Preserve the ORIGINAL wallet exception (name/message/stack/type) and the
   * exact stage that failed — an error like KasWare's WASM "unreachable" must
   * never surface as an opaque message again. Never logs secret material. */
  function walletStageError(e, diag) {
    if (e && e.walletStage) return e; // already enriched
    const name = (e && (e.name || (e.constructor && e.constructor.name))) || typeof e;
    const err = new Error(`[stage ${diag.stage} via ${diag.provider || "wallet"}] ${name}: ${(e && e.message) || String(e)}`);
    err.code = (e && e.code) || "WALLET_SIGN_FAILED";
    err.walletStage = diag.stage;
    err.original = { name, message: e && e.message, stack: e && e.stack, type: typeof e };
    try { console.error("[PolicyVault wallet-sign diagnostic]", { stage: diag.stage, provider: diag.provider, method: "signPskt/signInputs", name, message: e && e.message, stack: e && e.stack }); } catch { /* diagnostics must never mask the error */ }
    return err;
  }

  /* Sign through the canonical session, binding the signature to the expected
   * signer both BEFORE and AFTER the wallet popup (§10/§17): a mid-popup account
   * switch is refused rather than submitted. The server also re-authenticates.
   * Stage markers (B–K here; A/L/M/N live in the callers; H/J — PSKT decode +
   * signature extraction — are server-side at /approvals and /signature):
   *   B entered → C expected signer resolved → D canonical signInputs
   *   validated → E provider signPskt invoked → F returned → G returned shape
   *   checked → I post-popup signer re-verified → K returned to caller. */
  async function walletSign(unsignedSafeJson, signInputsList, expectedSigner, verification) {
    const diag = { stage: "B:walletSign-entered", provider: null };
    try {
      const s = session();
      diag.provider = s.provider || "wallet";
      if (!s.ready || !s.adapter) throw Object.assign(new Error(`wallet is not connected on ${networkLabel()}`), { code: "WALLET_NOT_READY" });
      diag.stage = "C:expected-signer-resolved";
      if (expectedSigner && s.address !== expectedSigner) throw Object.assign(new Error(`connected wallet ${short(s.address)} is not the expected signer ${short(expectedSigner)}`), { code: "SIGNER_MISMATCH" });
      diag.stage = "D:signInputs-validated";
      assertCanonicalSignInputs(signInputsList);
      // D2: MANDATORY browser verification binding whenever the verification
      // layer is loaded. The passing verification outcome must exist AND be
      // bound to the EXACT unsigned Safe JSON string being signed — a
      // refusal, an absent outcome, or a different payload never reaches the
      // wallet. Fail closed; there is no proceed-anyway.
      diag.stage = "D2:browser-verification-bound";
      if (verifyGate()) {
        if (!verification) {
          throw Object.assign(new Error("no browser verification outcome for this signing request — refusing to invoke the wallet"), { code: "VERIFICATION_REQUIRED" });
        }
        if (verification.ok !== true) {
          throw Object.assign(new Error(`browser verification REFUSED this transaction (${(verification.refusalCodes || []).join(", ")}) — refusing to invoke the wallet`), { code: "VERIFICATION_REFUSED" });
        }
        if (verification.unsignedSafeJson !== unsignedSafeJson) {
          throw Object.assign(new Error("the verified transaction payload is not the payload being signed — refusing to invoke the wallet"), { code: "VERIFICATION_TX_BINDING_MISMATCH" });
        }
      }
      diag.stage = "E:provider-signPskt-invoked";
      const signed = await s.adapter.signInputs(unsignedSafeJson, signInputsList, { network: s.network, expectedSignerAddress: expectedSigner || s.address });
      diag.stage = "F:provider-signPskt-returned";
      if (typeof signed !== "string" || !signed.trim()) throw Object.assign(new Error("wallet returned no signed transaction"), { code: "INVALID_SIGNATURE_RESPONSE" });
      diag.stage = "G:returned-shape-checked";
      const after = session();
      diag.stage = "I:post-popup-signer-verified";
      if (!after.ready || (expectedSigner && after.address !== expectedSigner)) {
        throw Object.assign(new Error("wallet account/network changed during signing — refusing to submit a signature from a different identity"), { code: "SIGNER_CHANGED" });
      }
      diag.stage = "K:walletSign-returned";
      return signed;
    } catch (e) {
      throw walletStageError(e, diag);
    }
  }

  /* Canonical review screen from a server-provided request.review. Scalar rows
   * are the normal human review; the server's `technical` sub-object (raw DAA
   * values etc.) renders read-only under an Advanced disclosure (§8).
   * onConfirm === null renders an INFORMATIONAL review (single Close button,
   * no signing action) — used when the durable server state says the request
   * is not signable by this wallet yet (e.g. AWAITING_APPROVALS). */
  function reviewModal(review, onConfirm, confirmLabel, headline, verification) {
    const rowsOf = (obj) => Object.entries(obj || {})
      .filter(([, v]) => v !== null && typeof v !== "object")
      .map(([k, v]) => `<tr><td class="rk">${esc(k)}</td><td class="rv">${esc(v)}</td></tr>`)
      .join("");
    const rows = rowsOf(review);
    const tech = review && review.technical && Object.keys(review.technical).length
      ? `<details class="adv"><summary>Advanced (technical)</summary><table class="review" style="width:100%">${rowsOf(review.technical)}</table></details>`
      : "";
    // ---- browser verification rendering (PostLaunchUpgradeOG) ----
    // With the verification layer loaded, a signing modal REQUIRES a passing
    // outcome: any refusal (or a missing outcome) renders the unmistakable
    // DO-NOT-SIGN state and NEVER offers a signing action. walletSign
    // enforces the same rule again before any provider call.
    const gate = verifyGate();
    let verifyHtml = "";
    let blocked = false;
    if (gate) {
      const v = verification;
      const lineDivs = (lines) => (lines || []).map((l) => `<div class="vline mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      if (v && v.ok === true) {
        const checkRows = (v.checks || []).map((c) => `<div class="mono" style="font-size:0.72rem">${c.ok ? "PASS" : "FAIL"} — ${esc(c.id)}</div>`).join("");
        const noteRows = (v.notes || []).map((n) => `<div class="hint" style="margin-top:0.2rem">${esc(n)}</div>`).join("");
        verifyHtml =
          `<div class="opbanner" style="border-color:var(--good);margin-top:0.8rem" data-verify="pass">` +
          `<b style="color:var(--good)">VERIFIED BY THIS BROWSER</b>` +
          `<div class="hint" style="margin-top:0.2rem">Independently re-derived in this browser from the exact transaction payload the wallet will sign and the values you entered — not from a server description.</div>` +
          `<div style="margin-top:0.4rem;font-size:0.78rem;max-height:14rem;overflow:auto">${lineDivs(v.lines)}</div>` +
          `<details class="adv"><summary>Verification details</summary>` +
          `<div class="mono" style="font-size:0.72rem;word-break:break-all">manifest hash ${esc(v.manifestHash || "")}<br/>transaction id ${esc(v.txId || "")}<br/>verdict ${esc(v.verdict)}</div>` +
          checkRows + noteRows + `</details></div>`;
      } else {
        blocked = !!onConfirm || !!v; // a refusal always renders; a signing modal is always blocked
        const lines = v && v.lines ? v.lines : ["!! DO NOT SIGN !!", "BROWSER VERIFICATION REFUSED — no verification outcome was produced for this signing request.", "Refusal codes: VERIFICATION_REQUIRED."];
        verifyHtml =
          `<div class="opbanner bad" style="margin-top:0.8rem;border-width:2px" data-verify="refused">` +
          `<b style="color:var(--bad);font-size:1rem">DO NOT SIGN</b>` +
          `<div style="margin-top:0.4rem;font-size:0.78rem;max-height:14rem;overflow:auto">${lineDivs(lines)}</div>` +
          (v && v.manifestHash ? `<details class="adv"><summary>Verification details</summary><div class="mono" style="font-size:0.72rem;word-break:break-all">manifest hash ${esc(v.manifestHash)}<br/>verdict ${esc(v.verdict || "REFUSED")}</div></details>` : "") +
          `</div>`;
      }
    } else {
      verifyHtml = `<div class="opbanner warn" style="margin-top:0.8rem" data-verify="unavailable">Independent browser verification is not loaded in this build — the review above is server-provided and was NOT independently re-verified by this browser.</div>`;
    }
    const canConfirm = !!onConfirm && !blocked;
    const actions = canConfirm
      ? `<div class="modal-actions"><button id="v4-cancel">Cancel</button>` +
        `<button id="v4-confirm" class="primary">${esc(confirmLabel || "Sign")}</button></div>`
      : `<div class="modal-actions"><button id="v4-cancel" class="primary">${esc(blocked ? "Close — do not sign" : confirmLabel || "Close")}</button></div>`;
    const m = $("v4-modal");
    m.innerHTML =
      `<div class="modal-card" style="max-width:560px;width:92%"><h3>${esc(blocked ? "DO NOT SIGN — verification refused" : headline || "Review — signed exactly as shown")}</h3>` +
      `<table class="review" style="width:100%">${rows}</table>` + tech + verifyHtml + actions + `</div>`;
    m.style.display = "flex";
    $("v4-cancel").onclick = () => { m.style.display = "none"; if (!canConfirm) render(); };
    const confirmBtn = $("v4-confirm");
    if (confirmBtn) confirmBtn.onclick = async () => {
      m.style.display = "none";
      await onConfirm();
    };
  }

  /* Sign the frozen request as its acting signer, FINALIZE, then LIVE
   * broadcast. Reached ONLY when the durable server state says the request is
   * signable now: below-threshold/owner requests directly after BUILD, and
   * above-threshold spends ONLY after all M approvals are collected (the
   * server independently re-refuses finalize otherwise). */
  async function completeRequestFlow(request, action, verification) {
    try {
      const signed = await walletSign(request.transaction.unsignedSafeJson, request.transaction.signInputs, state.address, verification);
      const done = await postJSON(`/wallet/v4/requests/${request.requestId}/signature`, { signedSafeJson: signed });
      if (done.request.state !== "PREFLIGHT_VERIFIED") {
        note(`${action}: ${done.request.state}${done.request.error ? " — " + done.request.error : ""}`, "warn");
        render();
        return;
      }
      note(`${action}: preflight OK — broadcasting to ${networkLabel()}…`, "warn");
      const sub = await postJSON(`/wallet/v4/requests/${request.requestId}/submit`, {});
      const ok = sub.request.state === "CHAIN_VERIFIED";
      note(`${action}: ${sub.request.state} — txid ${short(sub.txId)}${ok ? " (relayed + chain-verified)" : ""}`, ok ? "good" : "warn");
      render();
    } catch (e) {
      note(`${action} failed: ${e.code || ""} ${e.message}`, "bad");
    }
  }

  /* BUILD -> (approvals workflow | review -> sign) — DRIVEN BY THE SERVER'S
   * DURABLE REQUEST STATE. An above-threshold spend builds into
   * AWAITING_APPROVALS: the browser must NOT offer the agent-sign path — it
   * shows the informational review and hands off to the approval workflow on
   * the vault card (approvers sign first, the acting agent signs last).
   *
   * `extra` carries { proposalId } or { riskEvaluationId } on a RETRY after
   * a governance ceremony was satisfied or a risk hold was released — the
   * SAME build call, just with the consuming id attached (server/src/api.js
   * POST /wallet/v4/requests). This is the ONLY place either gate is consulted
   * (intent-stage, before any durable request exists), so a retry is simply
   * calling this function again — and a RELEASED risk hold needs no id at all: re-running the identical action plain lets the server match and consume the released review of this exact intent (RC-UX-1 continuation — see openRiskHold below). */
  async function runFlow(vaultId, action, params, confirmLabel, extra) {
    try {
      const { request } = await postJSON("/wallet/v4/requests", { vaultId, action, params, signerAddress: state.address, ...(extra || {}) });
      // BROWSER-LOCAL VERIFICATION of the freshly built request against the
      // CLIENT'S OWN action context (the params this browser just built from
      // the user's inputs — never the server's echo). `fuel` is the UTXO the
      // client itself selected; it is bound to the transaction too.
      const { fuel, ...clientParams } = params || {};
      const verification = verifyForSigning({
        request,
        vaultId,
        clientAction: action,
        clientParams,
        clientFuel: fuel,
        role: action === "agentSpend" ? "agent" : "owner"
      });
      if (request.state === "AWAITING_APPROVALS") {
        const p = request.approvalProgress || { collected: 0, required: request.review.approvalsRequired };
        note(`Approval request created — ${p.collected} of ${p.required} approvals collected. Approvers sign first; the agent signs after the threshold is met.`, "warn");
        reviewModal(request.review, null, "Close", `Awaiting approvals — ${p.collected} of ${p.required}`, verification);
        return;
      }
      reviewModal(request.review, () => completeRequestFlow(request, action, verification), confirmLabel, undefined, verification);
    } catch (e) {
      // GOVERNANCE_PROPOSAL_REQUIRED (409) / RISK_REVIEW_REQUIRED (409) /
      // RISK_DENIED (403): the server refused at the INTENT stage — the
      // refusal is never softened or bypassed here. When the ceremony/hold
      // UI module is loaded, hand off to the lawful path THROUGH the gate
      // (create+approve a proposal, or release+re-submit a hold); a page
      // served without those modules keeps the plain refusal note (fails
      // closed to "unavailable", never silently proceeds).
      if (e.code === "GOVERNANCE_PROPOSAL_REQUIRED" && govUI()) {
        return openGovernanceCeremony({ vaultId, action, params, confirmLabel, error: e });
      }
      if ((e.code === "RISK_REVIEW_REQUIRED" || e.code === "RISK_DENIED") && riskUI()) {
        return openRiskHold({ vaultId, action, params, confirmLabel, error: e });
      }
      note(`${action} rejected: ${e.code || ""} ${e.message}`, "bad");
    }
  }

  /* ===================== GOVERNANCE CEREMONY (item 1) =====================
   * Reached two ways:
   *   1. REACTIVE — runFlow's catch when the server refuses BUILD with
   *      GOVERNANCE_PROPOSAL_REQUIRED (`error` set; vaultId/action/params
   *      are the exact attempted action, still in hand).
   *   2. PERSISTENT LIST — clicking "View & act" on an OPEN proposal card
   *      rendered on a vault (`proposal` or `proposalId` set); the action
   *      to retry is recovered from the proposal's OWN stored content
   *      (governance.js's createProposal records the exact action+params
   *      requested), never re-typed or guessed by this layer.
   * Every field shown is the server's presentProposal() response,
   * verbatim (recomputed by the server at read time — governance-spec
   * §9.4). Approval signs THROUGH the existing session adapter
   * (adapter.signAuthMessage) — never a second signing path. */
  async function openGovernanceCeremony({ vaultId, action, params, confirmLabel, error, proposal, proposalId }) {
    const gov = govUI();
    if (!gov) {
      note(`${action || "action"} rejected: ${(error && error.code) || ""} ${(error && error.message) || "the governance ceremony UI failed to load"}`, "bad");
      return;
    }
    const m = $("v4-modal");
    const wireClose = () => {
      const b = m.querySelector("[data-gov-close]");
      if (b) b.onclick = () => { m.style.display = "none"; };
    };

    async function renderProposal(p) {
      const effectiveVaultId = vaultId || (p.proposal && p.proposal.vaultId);
      const effectiveAction = action || (p.proposal && p.proposal.action);
      const cstate = gov.ceremonyState(p, { xOnly: state.xonly });
      m.innerHTML = gov.renderProposalHtml(p, cstate);
      m.style.display = "flex";
      wireClose();
      const approveBtn = m.querySelector("[data-gov-approve]");
      if (approveBtn) approveBtn.onclick = async () => {
        approveBtn.disabled = true;
        try {
          const s = session();
          if (!s.ready || !s.adapter) throw Object.assign(new Error(`wallet is not connected on ${networkLabel()}`), { code: "WALLET_NOT_READY" });
          const updated = await gov.approve({ proposal: p, adapter: s.adapter, address: state.address, network: s.network });
          note("Governance approval recorded.", "good");
          await renderProposal(updated);
        } catch (e) {
          note(`Approval failed: ${e.code || ""} ${e.message}`, "bad");
          approveBtn.disabled = false;
        }
      };
      const retryBtn = m.querySelector("[data-gov-retry]");
      if (retryBtn) retryBtn.onclick = async () => {
        // Fuel-funded actions need a FRESH UTXO reference at retry time —
        // the stored proposal never carries `fuel` (governance.js strips
        // it as execution-only, not intent). agentSpend is reserve-funded
        // (no client-selected fuel) and passes params straight through.
        let effectiveParams = params || (p.proposal && p.proposal.params) || {};
        if (effectiveAction !== "agentSpend" && !effectiveParams.fuel) {
          const withFuelParams = await withFuel(effectiveParams);
          if (!withFuelParams) return; // withFuel already noted the reason
          effectiveParams = withFuelParams;
        }
        m.style.display = "none";
        runFlow(effectiveVaultId, effectiveAction, effectiveParams, confirmLabel || `Sign ${effectiveAction}`, { proposalId: p.proposalId });
      };
      const cancelBtn = m.querySelector("[data-gov-cancel]");
      if (cancelBtn) {
        const vault = state.vaultsById[effectiveVaultId];
        if (!vault || !state.xonly || state.xonly !== vault.owner) {
          cancelBtn.style.display = "none";
        } else {
          cancelBtn.onclick = async () => {
            if (!window.confirm("Cancel this governance proposal?\n\nCollected approvals are discarded. The vault itself is unaffected.")) return;
            try {
              await gov.cancelProposal(p.proposalId);
              note("Governance proposal cancelled.", "good");
              m.style.display = "none";
              render();
            } catch (e) { note(`Cancel failed: ${e.code || ""} ${e.message}`, "bad"); }
          };
        }
      }
    }

    if (proposal) { await renderProposal(proposal); return; }
    if (proposalId) {
      m.innerHTML = `<div class="modal-card" style="max-width:640px;width:92%"><h3 style="margin-top:0">Loading governance proposal…</h3></div>`;
      m.style.display = "flex";
      try { await renderProposal(await gov.fetchProposal(proposalId)); }
      catch (e) { note(`Could not load proposal: ${e.code || ""} ${e.message}`, "bad"); m.style.display = "none"; }
      return;
    }

    // REACTIVE entry: the server just refused BUILD with
    // GOVERNANCE_PROPOSAL_REQUIRED. Offer the lawful path — create the
    // proposal for the EXACT attempted action (the server independently
    // derives and validates the authority delta from vaultId/action/params;
    // this layer never computes or asserts a classification of its own).
    const gv = error && error.payload && error.payload.error && error.payload.error.governance;
    const summary = gv ? ` Classification: ${esc(gv.classification || "?")} [${esc((gv.codes || []).join(", "))}].` : "";
    m.innerHTML =
      `<div class="modal-card" style="max-width:640px;width:92%"><h3 style="margin-top:0">Governance proposal required</h3>` +
      `<div class="hint">${esc((error && error.message) || "This action requires an approved governance proposal.")}${summary}</div>` +
      `<div class="hint" style="margin-top:0.5rem">Creating a proposal does not change anything yet — it starts the ceremony. The exact authority delta is derived and validated by the server from this action, not by this page.</div>` +
      `<div class="modal-actions"><button class="primary" data-gov-createproposal="1">Create proposal for this action</button><button data-gov-close="1">Close</button></div></div>`;
    m.style.display = "flex";
    wireClose();
    const createBtn = m.querySelector("[data-gov-createproposal]");
    if (createBtn) createBtn.onclick = async () => {
      createBtn.disabled = true;
      try {
        const created = await gov.createProposalFor({ vaultId, action, params });
        note("Governance proposal created — collect the required approvals, then retry.", "good");
        await renderProposal(created);
      } catch (e) {
        note(`Create proposal failed: ${e.code || ""} ${e.message}`, "bad");
        createBtn.disabled = false;
      }
    };
  }

  /* ===================== RISK HOLD (item 2) =====================
   * Reached ONLY reactively: the server refused BUILD with
   * RISK_REVIEW_REQUIRED (409, a live hold to release) or RISK_DENIED
   * (403, final — server/src/risk.js gateOperationRisk never persists a
   * releasable DENY). There is no list-open-holds endpoint in the current
   * server API (server/src/api.js only serves GET /risk/evaluations/:id),
   * so a DIFFERENT authorized reviewer needs the evaluationId communicated
   * out of band (the Activity feed's risk audit rows carry it) — this
   * function also accepts a bare `evaluationId` for exactly that jump-in case.
   * SOLO CONTINUATION (RC-UX-1 fix): once a hold is RELEASED, the re-submit path here (which carries riskEvaluationId) is a convenience, not the only exit — the server also recognizes a plain re-attempt of the identical action from the vault card (exact reviewed intent, same vault, same risk-control configuration) and consumes the released hold exactly once (server/src/risk.js consumeReleasedHoldForIntent); a self-hosted solo operator who released via the API just re-runs the original action.
   * NEVER auto-released, NEVER retry-looped: both actions below are wired to explicit button clicks only. */
  async function openRiskHold({ vaultId, action, params, confirmLabel, error, evaluationId }) {
    const risk = riskUI();
    if (!risk) {
      note(`${action || "action"} rejected: ${(error && error.code) || ""} ${(error && error.message) || "the risk hold UI failed to load"}`, "bad");
      return;
    }
    const evalId = evaluationId || (error && error.payload && error.payload.error && error.payload.error.riskEvaluation && error.payload.error.riskEvaluation.evaluationId);
    if (!evalId) {
      note(`${action || "action"} rejected: ${(error && error.code) || ""} ${(error && error.message) || "no risk evaluation id was returned"}`, "bad");
      return;
    }
    const m = $("v4-modal");
    const wireClose = () => {
      const b = m.querySelector("[data-risk-close]");
      if (b) b.onclick = () => { m.style.display = "none"; };
    };

    async function renderEvaluation(ev) {
      const rstate = risk.holdState(ev, { xOnly: state.xonly });
      m.innerHTML = risk.renderEvaluationHtml(ev, rstate);
      m.style.display = "flex";
      wireClose();
      const releaseBtn = m.querySelector("[data-risk-release]");
      if (releaseBtn) releaseBtn.onclick = async () => {
        if (!window.confirm("Release this risk hold for execution?\n\nThis does not itself move funds — it only allows the original request to be re-submitted, where the covenant and the SDK's own policy checks still apply in full.")) return;
        releaseBtn.disabled = true;
        try {
          const updated = await risk.release(ev.evaluationId);
          note("Risk hold released.", "good");
          await renderEvaluation(updated);
        } catch (e) {
          note(`Release failed: ${e.code || ""} ${e.message}`, "bad");
          releaseBtn.disabled = false;
        }
      };
      const resubmitBtn = m.querySelector("[data-risk-resubmit]");
      if (resubmitBtn) resubmitBtn.onclick = () => {
        if (!vaultId || !action) {
          note("This risk hold was opened without the original action in hand — re-attempt the identical action from the vault card. The server recognizes an exact re-submission of this released, reviewed intent (same vault, same parameters, same risk-control configuration) and continues it, consuming the release exactly once.", "warn");
          return;
        }
        m.style.display = "none";
        runFlow(vaultId, action, params || {}, confirmLabel || `Sign ${action}`, { riskEvaluationId: ev.evaluationId });
      };
    }

    m.innerHTML = `<div class="modal-card" style="max-width:640px;width:92%"><h3 style="margin-top:0">Loading risk evaluation…</h3></div>`;
    m.style.display = "flex";
    try { await renderEvaluation(await risk.fetchEvaluation(evalId)); }
    catch (e) { note(`Could not load risk evaluation: ${e.code || ""} ${e.message}`, "bad"); m.style.display = "none"; }
  }

  /* One approver contribution: sign the covenant input of the EXACT frozen
   * transaction (the same bytes every other approver and the agent sign) and
   * submit it to the approver's own fixed slot. The signing metadata is the
   * CANONICAL FROZEN request.transaction.signInputs entry for the covenant
   * input — never reconstructed in the browser (the real-KasWare "unreachable"
   * incident came from a reconstructed entry that dropped sighashType). The
   * server verifies the signature against the connected approver's identity —
   * switching accounts never reinterprets an existing signature and never
   * changes the frozen bytes. */
  async function approve(req, verification) {
    let stage = "A:approve-entered";
    try {
      const t = req.transaction || {};
      const covenantIndex = t.covenantInputIndex;
      const entries = Array.isArray(t.signInputs) && Number.isInteger(covenantIndex)
        ? t.signInputs.filter((si) => si && si.index === covenantIndex)
        : [];
      if (entries.length !== 1) {
        throw Object.assign(new Error("request carries no canonical covenant-input signing entry — refusing to invoke the wallet"), { code: "SIGN_INPUTS_INVALID" });
      }
      const signed = await walletSign(t.unsignedSafeJson, entries, state.address, verification);
      stage = "L:post-approvals-started";
      const r = await postJSON(`/wallet/v4/requests/${req.requestId}/approvals`, { approverAddress: state.address, signedSafeJson: signed });
      stage = "M:server-response-received";
      note(`Approval recorded: ${r.approvals.collected} of ${r.approvals.required}${r.approvals.complete ? " — threshold met; the agent can now sign." : "."}`, "good");
      render(); // N: authoritative progress refreshed from server state
    } catch (e) {
      note(`Approval rejected${e.walletStage ? "" : ` [stage ${stage}]`}: ${e.code || ""} ${e.message}`, "bad");
    }
  }

  /* ===================== CREATE VAULT (friendly form) ===================== */
  // v0.4/v0.4.1 frozen consensus model: exactly 10 approver slots. UI limit
  // only mirrors it — the server/SDK independently rejects >10.
  const MAX_APPROVER_ROWS = 10;
  const PERIOD_PRESET_LABEL = { "1h": "1 hour", "6h": "6 hours", "1d": "1 day", "1w": "1 week" };
  // Client mirror of the server's supported product range (1 hour .. 53 weeks);
  // UX only — the server re-validates and stays authoritative.
  const PERIOD_UNIT_SECONDS = { hour: 3600n, day: 86400n, week: 604800n };
  const PERIOD_MIN_DAA = 36000n, PERIOD_MAX_DAA = 320544000n, DAA_PER_SEC = 10n;

  // Address-example placeholder for the CONFIGURED network (cosmetic only).
  const addrExample = () => (state.serverNetwork === "mainnet" ? "kaspa:..." : "kaspatest:...");

  // A new row is blank BY CONSTRUCTION — it never copies a previous row's value
  // (autocomplete stays off so the browser cannot re-fill it either).
  const rowHtml = (kind) =>
    `<div class="row"><input name="${kind}" class="mono" placeholder="${addrExample()}" autocomplete="off" />` +
    `<button type="button" class="rm-${kind}">Remove</button></div>`;
  const ferr = (key) => `<div class="ferr" data-err="${key}"></div>`;

  function createView() {
    return (
      `<div class="panel"><h3 style="margin-top:0">Create vault</h3>` +
      `<form class="cform" id="v4-create-form" autocomplete="off" novalidate>` +
      `<div class="full"><label>Vault name</label><input name="label" placeholder="Operations Treasury" />${ferr("label")}</div>` +
      `<div><label>Deposit (KAS)</label><input name="deposit" placeholder="100" inputmode="decimal" />${ferr("deposit")}</div>` +
      `<div><label>Fee reserve (KAS)</label><input name="reserve" placeholder="5" inputmode="decimal" />` +
      `<div class="hint">Pays permitted agent transaction fees without reducing protected principal. ${docsLink("fee-reserve")}</div>${ferr("reserve")}</div>` +
      `<div class="full"><label>Owner</label><div class="kv-line"><span class="mono">${esc(state.address)}</span> <span class="badge ver">Connected wallet</span></div></div>` +
      `<div class="full"><label>Initial agent — wallet address</label><input name="agent" class="mono" placeholder="${addrExample()}" autocomplete="off" />${ferr("agent")}` +
      `<div class="hint">A key the owner authorizes to spend from this vault, bounded by the policy below. ${docsLink("agent-delegate")}</div></div>` +
      `<div><label>Maximum per transaction (KAS)</label><input name="maxPerSpend" placeholder="2" inputmode="decimal" />${ferr("maxPerSpend")}` +
      `<div class="hint">Enforced by the covenant on every spend, regardless of who signs it. ${docsLink("per-transaction-limit")}</div></div>` +
      `<div><label>Budget per period (KAS)</label><input name="budget" placeholder="10" inputmode="decimal" />${ferr("budget")}</div>` +
      `<div><label>Budget resets approximately every</label><select name="period">` +
      `<option value="1h">1 hour</option><option value="6h">6 hours</option><option value="1d" selected>1 day</option><option value="1w">1 week</option>` +
      `<option value="custom">Custom…</option></select>` +
      `<div class="inline" id="v4-period-custom" style="display:none;margin-top:0.3rem">` +
      `<input name="periodValue" inputmode="numeric" placeholder="1" style="max-width:90px" />` +
      `<select name="periodUnit"><option value="hour">hours</option><option value="day">days</option><option value="week">weeks</option></select></div>` +
      // v4-period-hint's text is REPLACED via .textContent as the period
      // selector changes (see the input-change handler below) — a link
      // embedded inside it would be wiped on the first interaction, so the
      // docs link lives in its own static sibling instead, never touched.
      `<div class="hint" id="v4-period-hint">Budget resets approximately every 1 day.</div>` +
      `<div class="hint">A cumulative cap over a recurring window, tracked by the covenant using Kaspa consensus time. ${docsLink("periodic-budget")}</div>${ferr("period")}</div>` +
      `<div><label>Require approval above (KAS)</label><input name="approvalThreshold" placeholder="1" inputmode="decimal" />` +
      `<div class="hint">At or below: the agent may sign alone. Above: vault approval policy applies. ${docsLink("approval-threshold")}</div>${ferr("approvalThreshold")}</div>` +
      `<div class="full"><label>Allowed recipients</label><div class="reclist" id="v4-recipients">` +
      rowHtml("recipient") +
      `</div><button type="button" id="v4-add-recipient">+ Add recipient</button>${ferr("recipients")}` +
      `<div class="hint">The agent may only pay addresses on this list — enforced by the covenant, not just the server. ${docsLink("destination-allowlist")}</div></div>` +
      `<div class="full"><h4 style="margin:0.6rem 0 0.2rem">Approval policy (optional)</h4>` +
      `<label>Required approvals (M)</label><input name="approvalM" placeholder="0" inputmode="numeric" style="max-width:120px" />${ferr("approvalM")}` +
      `<div class="reclist" id="v4-approvers" style="margin-top:0.5rem"></div>` +
      `<button type="button" id="v4-add-approver">+ Add approver</button>` +
      ` <span class="hint" id="v4-approver-summary" style="display:inline"></span>` +
      `<div class="hint">Leave empty for an agent-only vault. Approvers are wallet addresses — at most 10, each distinct. An approver cannot spend vault funds or act as the owner. ${docsLink("external-approver")}</div>${ferr("approvers")}</div>` +
      `<div class="full"><details class="adv"><summary>Advanced</summary>` +
      `<div class="cform" style="margin-top:0.6rem">` +
      `<div><label>Maximum network fee per transaction (KAS)</label><input name="maxFee" placeholder="0.10" inputmode="decimal" /><div class="hint">Optional. Defaults to a safe value for current v0.4.1 fees.</div>${ferr("maxFee")}</div>` +
      `<div class="full hint">Technical detail: PolicyVault enforces budget periods using Kaspa DAA score, so wall-clock duration is approximate.</div>` +
      `</div></details></div>` +
      `<div class="full"><button type="submit" class="primary">Review vault…</button>` +
      `<span class="hint"> The owner wallet signs the funding transaction after review.</span></div>` +
      `</form></div>`
    );
  }

  /* ---- ONE-TIME delegated row wiring (the approver-row-multiplication fix).
   * This handler is attached to the persistent #v4-root EXACTLY ONCE at
   * startup — never inside render() — so re-renders (tab switches, wallet
   * session updates) can never accumulate duplicate listeners. One click adds
   * exactly one blank row; at 10 approver rows the add button is disabled and
   * clicks add nothing (no truncation — the rows simply cannot be created). */
  function handleCreateRowClick(e) {
    const t = e.target;
    if (!t || !t.classList) return;
    if (t.id === "v4-add-recipient") {
      const list = $("v4-recipients");
      if (list) list.insertAdjacentHTML("beforeend", rowHtml("recipient"));
    } else if (t.id === "v4-add-approver") {
      const list = $("v4-approvers");
      if (list && list.querySelectorAll(".row").length < MAX_APPROVER_ROWS) list.insertAdjacentHTML("beforeend", rowHtml("approver"));
    } else if (t.classList.contains("rm-recipient")) {
      const list = $("v4-recipients");
      if (list && list.querySelectorAll(".row").length > 1) t.closest(".row").remove();
    } else if (t.classList.contains("rm-approver")) {
      t.closest(".row").remove();
    } else {
      return;
    }
    syncCreateControls();
  }

  /* Keep the add-approver button + "M of N" summary in sync with the rows. */
  function syncCreateControls() {
    const f = $("v4-create-form");
    if (!f) return;
    const addBtn = $("v4-add-approver");
    const rows = $("v4-approvers") ? $("v4-approvers").querySelectorAll(".row").length : 0;
    if (addBtn) {
      addBtn.disabled = rows >= MAX_APPROVER_ROWS;
      addBtn.title = rows >= MAX_APPROVER_ROWS ? "Maximum of 10 approvers reached" : "";
    }
    const configured = $("v4-approvers") ? [...$("v4-approvers").querySelectorAll('[name="approver"]')].filter((i) => i.value.trim()).length : 0;
    const m = (f.querySelector('[name="approvalM"]')?.value ?? "").trim();
    const sum = $("v4-approver-summary");
    if (sum) sum.textContent = configured > 0 ? `${m || "?"} of ${configured} required` : "";
    const sel = f.querySelector('[name="period"]');
    const custom = $("v4-period-custom");
    if (sel && custom) custom.style.display = sel.value === "custom" ? "flex" : "none";
    const hint = $("v4-period-hint");
    if (hint && sel) {
      if (sel.value !== "custom") hint.textContent = `Budget resets approximately every ${PERIOD_PRESET_LABEL[sel.value] || sel.value}.`;
      else {
        const n = (f.querySelector('[name="periodValue"]')?.value ?? "").trim();
        const u = f.querySelector('[name="periodUnit"]')?.value ?? "hour";
        hint.textContent = /^[0-9]+$/.test(n) && Number(n) > 0 ? `Budget resets approximately every ${n} ${u}${n === "1" ? "" : "s"}.` : "Budget resets approximately every …";
      }
    }
  }

  /* Field-local error display: sets/clears .ferr blocks + input highlighting. */
  function showFieldErrors(f, errors) {
    f.querySelectorAll(".ferr").forEach((el) => { el.textContent = ""; el.classList.remove("show"); });
    f.querySelectorAll(".invalid").forEach((el) => el.classList.remove("invalid"));
    for (const [key, err] of errors) {
      const box = f.querySelector(`.ferr[data-err="${key}"]`);
      if (box) { box.textContent = err.message; box.classList.add("show"); }
      for (const el of err.inputs || []) el.classList.add("invalid");
    }
  }

  /*
   * Pre-Review validation (§ form validation). UX + defense-in-depth ONLY —
   * the server independently repeats every security-relevant validation and
   * remains authoritative. Addresses are checked through the server's ONE
   * address-identity boundary (/identity/resolve-address), which fails closed
   * on malformed / wrong-network / unsupported-type / bad-checksum input.
   * Returns { ok, errors: Map(fieldKey -> {message, inputs}), body }.
   */
  async function validateCreateForm(f) {
    const errors = new Map();
    const bad = (key, message, inputs) => { if (!errors.has(key)) errors.set(key, { message, inputs: inputs || [f.querySelector(`[name="${key}"]`)].filter(Boolean) }); };
    const v = (n) => (f.querySelector(`[name="${n}"]`)?.value ?? "").trim();
    const kas = (s) => kasToSompiClient(s);

    const label = v("label");
    if (!label) bad("label", "Vault name is required.");
    else if (label.length > 120) bad("label", "Vault name is too long (max 120 characters).");

    const deposit = kas(v("deposit"));
    if (deposit === null || BigInt(deposit) <= 0n) bad("deposit", "Enter a deposit greater than 0 KAS.");
    const reserve = kas(v("reserve"));
    if (reserve === null) bad("reserve", "Enter a fee reserve of 0 KAS or more.");

    const maxPerSpend = kas(v("maxPerSpend"));
    if (maxPerSpend === null || BigInt(maxPerSpend) <= 0n) bad("maxPerSpend", "Enter a maximum per transaction greater than 0 KAS.");
    const budget = kas(v("budget"));
    if (budget === null || BigInt(budget) <= 0n) bad("budget", "Enter a budget greater than 0 KAS.");
    else if (maxPerSpend !== null && BigInt(budget) < BigInt(maxPerSpend)) bad("budget", "Budget must be at least the maximum per transaction.");

    const threshold = kas(v("approvalThreshold"));
    if (threshold === null) bad("approvalThreshold", "Enter an approval threshold (0 KAS means every spend needs approval).");

    const maxFee = v("maxFee");
    if (maxFee && (kas(maxFee) === null || BigInt(kas(maxFee)) <= 0n)) bad("maxFee", "Maximum network fee must be a positive KAS amount.");

    // Budget period: preset, or custom {value, unit} within the product range.
    const preset = v("period");
    let budgetPeriod = preset;
    if (preset === "custom") {
      const n = v("periodValue");
      const unit = v("periodUnit") || "hour";
      if (!/^[0-9]+$/.test(n) || BigInt(n) <= 0n) {
        bad("period", "Enter a whole number of hours, days, or weeks.", [f.querySelector('[name="periodValue"]')]);
      } else if (!PERIOD_UNIT_SECONDS[unit]) {
        bad("period", "Choose hours, days, or weeks.", [f.querySelector('[name="periodUnit"]')]);
      } else {
        const daa = BigInt(n) * PERIOD_UNIT_SECONDS[unit] * DAA_PER_SEC;
        if (daa < PERIOD_MIN_DAA || daa > PERIOD_MAX_DAA) {
          bad("period", "Budget period must be between 1 hour and 53 weeks.", [f.querySelector('[name="periodValue"]')]);
        }
        budgetPeriod = { value: n, unit };
      }
    }

    // Address checks share one resolution pass (server-authoritative identity).
    const cache = new Map();
    const resolve = async (addr) => {
      if (!cache.has(addr)) {
        try { cache.set(addr, { x: await resolveXOnly(addr) }); }
        catch (err) { cache.set(addr, { err: err.message || "invalid address" }); }
      }
      return cache.get(addr);
    };

    const agentAddr = v("agent");
    let agentXOnly = null;
    if (!agentAddr) bad("agent", "Enter the initial agent's wallet address.");
    else {
      const r = await resolve(agentAddr);
      if (r.err) bad("agent", `Agent address rejected: ${r.err}`);
      else agentXOnly = r.x;
    }

    // Recipients: at least one; a blank row must be filled or removed; each
    // address must resolve on the server's configured network.
    const recipientInputs = [...f.querySelectorAll('[name="recipient"]')];
    const recipientAddresses = [];
    const recipientXOnlys = [];
    const recipientMsgs = [];
    const recipientBad = [];
    for (let i = 0; i < recipientInputs.length; i++) {
      const a = recipientInputs[i].value.trim();
      if (!a) {
        if (recipientInputs.length > 1) { recipientMsgs.push(`Recipient ${i + 1}: enter an address or remove the row.`); recipientBad.push(recipientInputs[i]); }
        continue;
      }
      const r = await resolve(a);
      if (r.err) { recipientMsgs.push(`Recipient ${i + 1}: ${r.err}`); recipientBad.push(recipientInputs[i]); }
      else { recipientAddresses.push(a); recipientXOnlys.push(r.x); }
    }
    if (!recipientMsgs.length && recipientAddresses.length === 0) recipientMsgs.push("Add at least one allowed recipient address.");
    if (recipientMsgs.length) bad("recipients", recipientMsgs.join(" "), recipientBad.length ? recipientBad : recipientInputs);

    // Approvers: max 10 rows; every configured row must hold a valid address;
    // duplicates are rejected BOTH as wallet addresses and as resolved x-only
    // identities; an empty row is never silently counted as configured.
    const approverInputs = [...f.querySelectorAll('[name="approver"]')];
    const approverAddresses = [];
    const approverXOnlys = [];
    const approverMsgs = [];
    const approverBad = [];
    const seenAddr = new Map();
    const seenX = new Map();
    if (approverInputs.length > MAX_APPROVER_ROWS) approverMsgs.push(`At most ${MAX_APPROVER_ROWS} approvers are supported.`);
    for (let i = 0; i < approverInputs.length; i++) {
      const a = approverInputs[i].value.trim();
      if (!a) { approverMsgs.push(`Approver ${i + 1}: enter an address or remove the row.`); approverBad.push(approverInputs[i]); continue; }
      if (seenAddr.has(a)) { approverMsgs.push(`Approver ${i + 1} duplicates approver ${seenAddr.get(a) + 1}.`); approverBad.push(approverInputs[i]); continue; }
      seenAddr.set(a, i);
      const r = await resolve(a);
      if (r.err) { approverMsgs.push(`Approver ${i + 1}: ${r.err}`); approverBad.push(approverInputs[i]); continue; }
      if (seenX.has(r.x)) { approverMsgs.push(`Approver ${i + 1} is the same signing identity as approver ${seenX.get(r.x) + 1}.`); approverBad.push(approverInputs[i]); continue; }
      seenX.set(r.x, i);
      approverAddresses.push(a);
      approverXOnlys.push(r.x);
    }
    if (approverMsgs.length) bad("approvers", approverMsgs.join(" "), approverBad);

    // Required approvals M: 0 <= M <= 10, M <= valid configured approvers,
    // and M >= 1 whenever approvers are configured. Never inferred.
    const mRaw = v("approvalM");
    const configured = approverAddresses.length;
    let approvalM = null;
    if (approverInputs.length === 0) {
      if (mRaw && mRaw !== "0") bad("approvalM", "Add approver rows first, or leave required approvals empty.");
    } else {
      if (!/^[0-9]+$/.test(mRaw)) bad("approvalM", "Enter how many approvals are required (a whole number).");
      else {
        const m = Number(mRaw);
        if (m > MAX_APPROVER_ROWS) bad("approvalM", `Required approvals cannot exceed ${MAX_APPROVER_ROWS}.`);
        else if (m < 1) bad("approvalM", "Required approvals must be at least 1 when approvers are configured.");
        else if (!errors.has("approvers") && m > configured) bad("approvalM", `Required approvals (${m}) exceeds the ${configured} configured approver${configured === 1 ? "" : "s"}.`);
        else approvalM = String(m);
      }
    }

    if (errors.size) return { ok: false, errors, body: null, context: null };
    const body = {
      contractVersion: "policyvault-0.4.1",
      signerAddress: state.address,
      vaultId: randomHex32(),
      label,
      depositKas: v("deposit"),
      feeReserveKas: v("reserve"),
      agent: {
        agentAddress: agentAddr,
        maxPerSpendKas: v("maxPerSpend"),
        budgetKas: v("budget"),
        budgetPeriod,
        approvalThresholdKas: v("approvalThreshold"),
        ...(maxFee ? { maxFeePerTxKas: maxFee } : {}),
        recipientAddresses
      }
    };
    if (approverAddresses.length) body.approvers = { addresses: approverAddresses, approvalM };
    // CLIENT-SIDE create context for browser-local genesis verification:
    // the values THIS browser derived from the user's inputs (the generated
    // vaultId, typed amounts, the resolved approver/agent/recipient
    // identities, the typed agent policy) — captured BEFORE the server
    // ever sees the request. The agent policy fields pin the DISCLOSED
    // genesis registry tuple (residuals wave: web/verify-intent.js
    // recomputes the genesis agentRoot from request.initialRegistry and
    // cross-checks these typed values against the committed tuple).
    const context = {
      vaultId: body.vaultId,
      depositKas: v("deposit"),
      feeReserveKas: v("reserve"),
      approvalM: approverAddresses.length ? approvalM : "0",
      approverXOnlys,
      agentXOnly,
      agentMaxPerSpendKas: v("maxPerSpend"),
      agentBudgetKas: v("budget"),
      agentApprovalThresholdKas: v("approvalThreshold"),
      ...(maxFee ? { agentMaxFeePerTxKas: maxFee } : {}),
      agentRecipientXOnlys: recipientXOnlys,
      ...(maxFee ? { maxFeeSompi: kas(maxFee) } : {})
    };
    return { ok: true, errors, body, context };
  }

  /* Wire the freshly rendered create form (the form element is NEW on each
   * render, so these listeners die with it — row add/remove wiring lives in
   * the one-time delegated handler above instead). */
  function wireCreateForm() {
    const f = $("v4-create-form");
    if (!f) return;
    f.addEventListener("input", () => syncCreateControls());
    f.addEventListener("change", () => syncCreateControls());
    syncCreateControls();
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = f.querySelector('button[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;
      try {
        note("Checking the form…", "warn");
        const { ok, errors, body, context } = await validateCreateForm(f);
        showFieldErrors(f, errors);
        if (!ok) { note("Fix the highlighted fields, then Review again.", "bad"); return; }
        let built;
        try {
          note("Building vault…", "warn");
          built = await postJSON("/wallet/v4/create", body);
        } catch (err) {
          note(`Create rejected: ${err.code || ""} ${err.message}`, "bad");
          return;
        }
        const request = built.request;
        // BROWSER-LOCAL GENESIS VERIFICATION against the client's own form
        // context (client-generated vaultId, typed deposit/reserve, resolved
        // approver identities, the connected owner identity).
        const verification = verifyForSigning({ request, createContext: context, role: "owner" });
        reviewModal(request.review, async () => {
          try {
            const signed = await walletSign(request.transaction.unsignedSafeJson, request.transaction.signInputs, state.address, verification);
            note(`Creating vault — broadcasting genesis to ${networkLabel()}…`, "warn");
            const done = await postJSON(`/wallet/v4/requests/${request.requestId}/genesis-submit`, { signedSafeJson: signed });
            const ok2 = done.request.state === "CHAIN_VERIFIED";
            note(`Vault created: ${done.request.state} — txid ${short(done.txId)}${ok2 ? " (chain-verified)" : ""}`, ok2 ? "good" : "warn");
            if (ok2) { state.view = "vaults"; state.statusFilter = "Active"; }
            render();
          } catch (err) {
            note(`Create failed: ${err.code || ""} ${err.message}`, "bad");
          }
        }, "Sign & create", undefined, verification);
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  /* ===================== VAULT CARDS (§21 hierarchy) ===================== */
  /* Terminal (closed) vaults are permanently READ-ONLY history: no control
   * that could produce a transaction is ever rendered for them, and the
   * server independently rejects any write (VAULT_TERMINAL). */
  const isTerminalVault = (vault) => vault.status === "RECOVERED" || vault.status === "TERMINATED_UNKNOWN" || !vault.live;

  /* Hosted suspension state for a vault, as loaded by render(). Returns
   * null while unknown (not fetched / terminal), an {error} record when
   * the load failed (FAIL-CLOSED: unknown state renders as unknown and
   * offers no flip controls), or the server's presented record. */
  function suspOf(vault) {
    return (state.suspByVault && state.suspByVault[vault.vaultId]) || null;
  }
  function agentSuspended(vault, agentPk) {
    const s = suspOf(vault);
    if (!s || s.error) return false; // marker only — unknown renders via the card banner, not per-agent
    return s.allAgents || s.agents.includes(agentPk);
  }

  function agentCard(vault, agent) {
    const terminal = isTerminalVault(vault);
    const isThisAgent = state.xonly && state.xonly === agent.agentPk;
    const spend = isThisAgent && !terminal && vault.status === "ACTIVE" ? `<button class="primary" data-spend="${esc(agent.agentPk)}">Spend</button>` : "";
    const susp = suspOf(vault);
    const suspKnown = !!(susp && !susp.error);
    const suspended = suspKnown && agentSuspended(vault, agent.agentPk);
    // Visible to every participant (agents can see they are suspended);
    // "hosted" is stated so it is never mistaken for the covenant pause.
    const suspMark = suspended ? ` <span class="badge PAUSED">SUSPENDED (hosted)</span>` : "";
    // The per-agent flip button is offered ONLY on known suspension state
    // (fail-closed) and only to the owner. The all-agents flag is lifted
    // via the vault-level control, not per-agent.
    const suspBtn = !suspKnown
      ? ""
      : susp.allAgents
        ? ""
        : susp.agents.includes(agent.agentPk)
          ? `<button data-unsuspend="${esc(agent.agentPk)}">Unsuspend (hosted)</button>`
          : `<button class="warn" data-suspend="${esc(agent.agentPk)}">Suspend (hosted)</button>`;
    return (
      `<div class="field" style="margin-top:0.5rem">` +
      `<div class="k">agent ${isThisAgent ? "(you)" : ""}${terminal ? " (historical)" : ""}${suspMark}</div>` +
      `<div class="v">cap ${esc(agent.maxPerSpendKas)} KAS · budget ${esc(agent.remainingBudgetKas)}/${esc(agent.periodBudgetKas)} KAS · approval&gt; ${esc(agent.approvalThresholdKas)} KAS ${spend}</div>` +
      (state.xonly === vault.owner && !terminal ? `<div class="actions"><button data-repolicy="${esc(agent.agentPk)}">Re-policy</button><button data-rotate="${esc(agent.agentPk)}">Rotate key</button><button class="warn" data-remove="${esc(agent.agentPk)}">Remove</button>${suspBtn}</div>` : "") +
      `</div>`
    );
  }

  /* Suspension banner for the vault card. Renders the server's
   * NOT_COVENANT_NOTICE VERBATIM with any active suspension so the
   * control is never mistaken for on-chain enforcement (it pairs with —
   * never replaces — the covenant Pause / Remove controls rendered
   * alongside). Unknown state renders honestly as unknown. */
  function suspensionBanner(vault) {
    const susp = suspOf(vault);
    if (!susp) return "";
    if (susp.error) {
      return `<div class="opbanner warn" style="margin-top:0.5rem"><b>Hosted agent-suspension state unavailable</b> (${esc(susp.error)}) — treating it as UNKNOWN; suspend/unsuspend controls are disabled until it loads. Covenant controls (Pause, Remove agent) are unaffected.</div>`;
    }
    const active = susp.allAgents || susp.agents.length > 0;
    if (!active) return "";
    const registryPks = new Set((vault.agents || []).map((a) => a.agentPk));
    const stale = susp.agents.filter((a) => !registryPks.has(a));
    const scope = susp.allAgents
      ? `ALL agents${susp.agents.length ? ` (+${susp.agents.length} per-agent entr${susp.agents.length === 1 ? "y" : "ies"})` : ""}`
      : `${susp.agents.length} agent${susp.agents.length === 1 ? "" : "s"}`;
    return (
      `<div class="opbanner warn" style="margin-top:0.5rem" data-suspbanner="${esc(vault.vaultId)}">` +
      `<b>Hosted suspension active — ${esc(scope)}</b>` +
      `<div class="hint" style="margin-top:0.2rem">${esc(susp.notice || "")}</div>` +
      (stale.length && state.xonly === vault.owner && !isTerminalVault(vault)
        ? `<div class="hint" style="margin-top:0.3rem">Stale entries (keys no longer in the agent registry): ${stale.map((a) => `<span class="mono">${esc(short(a))}</span> <button data-unsuspend="${esc(a)}">Unsuspend (hosted)</button>`).join(" ")}</div>`
        : "") +
      `</div>`
    );
  }
  /* One pending above-threshold approval request, rendered from the SERVER'S
   * durable state (GET /wallet/v4/requests?open=1). Role-scoped actions:
   *   - an approver with an unfilled slot: Review & approve;
   *   - an approver who signed: progress only;
   *   - the acting agent while approvals are outstanding: progress only
   *     (approvers sign first — the agent-sign path is NOT offered);
   *   - the acting agent once M-of-N is complete: Review & sign spend;
   *   - any unrelated wallet: read-only progress, no authority.
   * Cancel (agent or owner) rejects the durable request explicitly. */
  function approvalRequestCard(vault, req) {
    const sentinel = "00".repeat(32);
    const p = req.approvalProgress || { collected: 0, required: Number((req.review && req.review.approvalsRequired) || 0), approvedSlots: null, approverSlots: null };
    const slots = (p.approverSlots && p.approverSlots.length ? p.approverSlots : (vault.approverSlots || [])).filter((s) => s !== sentinel);
    const myIdx = state.xonly ? slots.indexOf(state.xonly) : -1;
    const iApproved = myIdx >= 0 && Array.isArray(p.approvedSlots) ? !!p.approvedSlots[myIdx] : false;
    const isActingAgent = state.address === req.signerAddress;
    const awaiting = req.state === "AWAITING_APPROVALS";
    let action = "";
    if (awaiting && myIdx >= 0 && !iApproved) action = `<button class="primary" data-approvereq="${esc(req.requestId)}">Review &amp; approve</button>`;
    else if (awaiting && myIdx >= 0 && iApproved) action = `<span class="hint" style="display:inline">You approved — waiting for the remaining approvals.</span>`;
    else if (!awaiting && isActingAgent) action = `<button class="primary" data-agentsign="${esc(req.requestId)}">Review &amp; sign spend</button>`;
    else if (awaiting && isActingAgent) action = `<span class="hint" style="display:inline">Approvers sign first; you sign after the threshold is met.</span>`;
    const cancel = isActingAgent || (state.xonly && state.xonly === vault.owner)
      ? ` <button class="warn" data-cancelreq="${esc(req.requestId)}">Cancel request</button>` : "";
    const to = (req.review && (req.review.recipientAddress || req.review.recipient)) || "";
    return (
      `<div class="opbanner warn" data-reqcard="${esc(req.requestId)}">` +
      `<b>${awaiting ? "Awaiting approvals" : "Approved — awaiting agent signature"}</b> · ` +
      `${esc(String(p.collected))} of ${esc(String(p.required))} approved · ` +
      `${esc((req.review && req.review.paymentKas) || "?")} KAS to ${esc(short(to))} · request ${esc(short(req.requestId))}` +
      ` ${action}${cancel}</div>`
    );
  }

  function vaultCard(vault, openRequests = [], governanceProposals = []) {
    const isOwner = state.xonly && state.xonly === vault.owner;
    const live = vault.live || {};
    const opStatus = (vault.operational && vault.operational.status) || vault.status;
    const terminal = isTerminalVault(vault);
    const badge = vault.status === "ACTIVE" ? "ACTIVE" : vault.status === "PAUSED" ? "PAUSED" : "RECOVERED";
    const approverCount = (vault.approverSlots || []).filter((s) => s !== "00".repeat(32)).length;
    // The hosted all-agents suspend flip is offered ONLY on known
    // suspension state (fail-closed) — and always NEXT TO the covenant
    // Pause control it can never replace.
    const suspV = suspOf(vault);
    const suspAllBtn = suspV && !suspV.error
      ? suspV.allAgents
        ? `<button data-unsuspendall="${esc(vault.vaultId)}">Unsuspend all (hosted)</button>`
        : `<button class="warn" data-suspendall="${esc(vault.vaultId)}">Suspend all agents (hosted)</button>`
      : "";
    const ownerControls = isOwner && !terminal
      ? `<div class="actions"><button data-addagent="${esc(vault.vaultId)}">Add agent</button>` +
        `<button data-topup="${esc(vault.vaultId)}">Top up principal</button><button data-topupreserve="${esc(vault.vaultId)}">Top up fee reserve</button>` +
        `<button data-setapprovers="${esc(vault.vaultId)}">Set approvers</button>` +
        (live.paused ? `<button data-unpause="${esc(vault.vaultId)}">Unpause</button>` : `<button data-pause="${esc(vault.vaultId)}">Pause</button>`) +
        docsHintIcon("pause-and-revoke", "Pause: the owner's immediate, break-glass freeze on a vault, independent of any hosted workflow.") +
        suspAllBtn +
        `<button data-verify="${esc(vault.vaultId)}">Verify state</button>` +
        `<button class="warn" data-recover="${esc(vault.vaultId)}">Close &amp; recover</button>` +
        docsHintIcon("owner-recovery", "Owner recovery: a terminal, owner-signed break-glass operation to withdraw the vault's funds, independent of any hosted workflow.") +
        `</div>`
      : "";
    // Live value fields render ONLY while live state exists. A closed vault
    // shows its terminal status without fabricating historical numbers (the
    // durable history lives in Details / Activity), and never a misleading
    // "0-of-0" approval policy.
    const grid = terminal
      ? `<div class="kv-line" style="margin-top:0.4rem">This vault is closed${vault.status === "RECOVERED" ? " — remaining funds were recovered to the owner at closure (see Details / Activity for the terminal transaction)" : " — its terminal state could not be automatically classified; see Details / Activity"}. It is read-only history.</div>`
      : `<div class="grid">` +
        `<div class="field"><div class="k">Protected</div><div class="v">${esc(live.protectedValueKas || "—")} KAS</div></div>` +
        `<div class="field"><div class="k">Fee reserve</div><div class="v">${esc(live.feeReserveKas || "—")} KAS</div></div>` +
        `<div class="field"><div class="k">Agents</div><div class="v">${(vault.agents || []).length}</div></div>` +
        `<div class="field"><div class="k">Approvals</div><div class="v">${esc(live.approvalM || "0")}-of-${approverCount}</div></div>` +
        `</div>`;
    return (
      `<div class="vault" data-vault="${esc(vault.vaultId)}">` +
      `<div class="vault-head"><span class="vault-title">${esc(vault.label || short(vault.vaultId))}</span> ` +
      `<span><span class="badge ${badge}">${esc(opStatus)}</span> <span class="badge ver">${esc(vault.contractVersion)}</span></span></div>` +
      grid +
      // Organization assignment — application metadata only; grants no Kaspa
      // covenant authority and never changes on-chain state.
      `<div class="org-assign">Organization ` +
      `<select data-orgassign="${esc(vault.vaultId)}"><option value=""${!(vault.organization && vault.organization.orgId) ? " selected" : ""}>Unassigned</option>` +
      ((state.orgData && state.orgData.organizations) || [])
        .filter((o) => !o.error && (o.status !== "ARCHIVED" || (vault.organization && vault.organization.orgId === o.orgId)))
        .map((o) => `<option value="${esc(o.orgId)}"${vault.organization && vault.organization.orgId === o.orgId ? " selected" : ""}>${esc(o.name)}${o.status === "ARCHIVED" ? " (archived)" : ""}</option>`)
        .join("") +
      `</select></div>` +
      suspensionBanner(vault) +
      (vault.agents || []).map((a) => agentCard(vault, a)).join("") +
      openRequests.map((r) => approvalRequestCard(vault, r)).join("") +
      // Open governance proposals awaiting ceremony (item 1 persistent
      // surface): a DIFFERENT owner/quorum wallet than the one that hit
      // GOVERNANCE_PROPOSAL_REQUIRED needs to find and act on this proposal
      // on its own later visit — mirrors the approvalRequestCard pattern.
      (govUI() ? governanceProposals.map((p) => govUI().renderCompactCard(p)).join("") : "") +
      ownerControls +
      `<details class="adv"><summary>Details</summary><div class="mono id">` +
      `vaultId ${esc(vault.vaultId)}<br/>contract ${esc(vault.contractVersion)}` +
      (terminal ? "" : `<br/>policyNonce ${esc(live.policyNonce || "—")}<br/>agentRoot ${esc(live.agentRoot || "—")}`) +
      (live.outpoint ? `<br/>live outpoint ${esc(live.outpoint.transactionId || "")}:${esc(String(live.outpoint.index ?? ""))}` : "") +
      (live.covenantId ? `<br/>covenant id ${esc(live.covenantId)}` : "") +
      (vault.creationTxId ? `<br/>creation tx ${esc(vault.creationTxId)}` : "") +
      (vault.latestTransitionTxId ? `<br/>${terminal ? "terminal" : "latest"} tx ${esc(vault.latestTransitionTxId)}` : "") +
      `</div></details></div>`
    );
  }

  /* §17/§18: status filter + operational sort priority. */
  const STATUS_RANK = { ACTION_REQUIRED_VERIFY: 0, RECONCILIATION_REQUIRED: 1, WAITING_FOR_SIGNATURE: 2, TRANSACTION_PENDING: 3, ACTIVE: 4, PAUSED: 4, UNKNOWN: 5, CLOSED: 6, RECOVERED: 6, TERMINATED_UNKNOWN: 6 };
  function opOf(v) { return (v.operational && v.operational.status) || (v.status === "RECOVERED" || v.status === "TERMINATED_UNKNOWN" ? "CLOSED" : v.status) || "UNKNOWN"; }
  function isClosed(v) { return v.status === "RECOVERED" || v.status === "TERMINATED_UNKNOWN" || opOf(v) === "CLOSED"; }
  function needsAction(v) { return ["ACTION_REQUIRED_VERIFY", "RECONCILIATION_REQUIRED", "WAITING_FOR_SIGNATURE", "TRANSACTION_PENDING", "UNKNOWN"].includes(opOf(v)); }
  function matchesFilter(v) {
    if (state.statusFilter === "All") return true;
    if (state.statusFilter === "Closed") return isClosed(v);
    if (state.statusFilter === "Needs Action") return needsAction(v) && !isClosed(v);
    return !isClosed(v) && !needsAction(v); // Active
  }

  /* Organization filter: All / Unassigned / each ACTIVE organization.
   * Archived organizations never appear here — manage them in the
   * Organizations view. */
  function filterBar(activeOrgs, counts) {
    const pill = (name) => `<button class="pill${state.statusFilter === name ? " active" : ""}" data-status="${esc(name)}">${esc(name)}${counts[name] != null ? ` (${counts[name]})` : ""}</button>`;
    const orgOpts =
      `<option value="all">All organizations</option>` +
      `<option value="unassigned"${state.org === "unassigned" ? " selected" : ""}>Unassigned</option>` +
      activeOrgs.map((o) => `<option value="${esc(o.orgId)}"${state.org === o.orgId ? " selected" : ""}>${esc(o.name)}</option>`).join("");
    return (
      `<div class="filterbar"><label class="k">Organization</label><select id="v4-org">${orgOpts}</select>` +
      `<span style="width:0.6rem"></span>` +
      ["Active", "Needs Action", "Closed", "All"].map(pill).join("") + `</div>`
    );
  }

  /* ===================== RENDER ===================== */
  async function render() {
    const root = $("v4-root");
    if (!root) return;
    state.renderedOnce = true;
    // Stale-render guard: renders that await network data must NOT write the
    // DOM if a newer render started meanwhile (e.g. the user opened the Create
    // view while a vaults render was still fetching — the late completion
    // would clobber the fresh form).
    const seq = (state.renderSeq = (state.renderSeq || 0) + 1);
    const stale = () => seq !== state.renderSeq;
    // nav highlight
    document.querySelectorAll(".v4-tab").forEach((b) => b.classList.toggle("active", b.dataset.view === state.view));
    // Not ready = not connected OR not on the server's configured network ->
    // no privileged actions.
    if (!state.ready) {
      root.innerHTML = state.address
        ? `<div class="empty">Wallet is not on ${esc(networkLabel())}. Signing is disabled until you switch KasWare to ${esc(networkLabel())}.</div>`
        : `<div class="empty">Connect KasWare in the Wallet panel above to begin.</div>`;
      return;
    }
    if (state.view === "create") { root.innerHTML = createView(); wireCreateForm(); return; }
    if (state.view === "orgs") { await renderOrgsView(root, stale); return; }
    if (state.view === "activity") { await renderActivityView(root, stale); return; }
    if (state.view === "support") { await renderSupportView(root, stale); return; }
    if (state.view === "advanced") {
      root.innerHTML = `<div class="panel"><h3 style="margin-top:0">Advanced</h3><div class="kv-line">Connected: <span class="mono">${esc(state.address)}</span> (x-only <span class="mono">${esc(short(state.xonly))}</span>) · network ${esc(state.network)}</div><div class="hint" style="margin-top:0.6rem">Legacy vault compatibility: existing v0.2 / v0.3 vaults remain supported for management, verification, history, and recovery in the collapsed section at the bottom of the page. New vaults always use the current protocol.</div></div>`;
      return;
    }
    // vaults view
    let vaults;
    try {
      ({ vaults } = await getJSON("/vaults"));
    } catch (e) {
      if (!stale()) root.innerHTML = `<div class="empty">Could not load vaults: ${esc(e.message)}</div>`;
      return;
    }
    let orgData = { organizations: [], assignments: {}, assignmentsVersion: null };
    try { orgData = await getJSON("/organizations"); } catch { /* metadata failure never blocks vaults */ }
    // Durable pending-approval requests (server state — survives reloads).
    let openReqs = [];
    try { ({ requests: openReqs = [] } = await getJSON("/wallet/v4/requests?open=1")); } catch { openReqs = []; }
    // Open governance proposals awaiting ceremony (item 1 persistent
    // surface). Best-effort: a page served without the governance-ui
    // module, or a server that refuses the list route, simply shows no
    // proposal cards — it never blocks the vaults view.
    let govProposals = [];
    const gov0 = govUI();
    if (gov0) { try { govProposals = await gov0.fetchOpenProposals(); } catch { govProposals = []; } }
    // Hosted-layer agent-suspension state per live v4 vault (surface 21
    // web composition; GET /vaults/:id/agent-suspensions — COORDINATION
    // CONTROL ONLY, never a covenant control; the server's verbatim
    // notice is rendered with the state). FAIL-CLOSED RENDERING: a vault
    // whose suspension state cannot be loaded records the error and the
    // card treats the state as UNKNOWN — it never renders "not suspended"
    // and never offers the flip controls on unknown state.
    const suspByVault = {};
    await Promise.all(
      (vaults || [])
        .filter((v) => v && v.vaultId && new Set(["policyvault-0.4", "policyvault-0.4.1"]).has(v.contractVersion) && !isTerminalVault(v))
        .map(async (v) => {
          try {
            const { suspensions } = await getJSON(`/vaults/${v.vaultId}/agent-suspensions`);
            suspByVault[v.vaultId] = suspensions && suspensions.schema && typeof suspensions.allAgents === "boolean" && Array.isArray(suspensions.agents)
              ? suspensions
              : { error: "unrecognized suspension record shape" };
          } catch (e) {
            suspByVault[v.vaultId] = { error: `${e.code ? `${e.code} ` : ""}${e.message}` };
          }
        })
    );
    if (stale()) return;
    state.suspByVault = suspByVault;
    state.orgData = orgData;
    // Client-side vault knowledge snapshot for browser-local pre-sign
    // verification: the exact vault presentations the user is looking at.
    state.vaultsById = {};
    for (const v of vaults || []) { if (v && v.vaultId) state.vaultsById[v.vaultId] = v; }
    // Surface only the above-threshold approval workflow here; plain BUILT
    // below-threshold requests complete inside their own modal flow.
    state.openReqs = openReqs.filter((r) => r && r.aboveThreshold);
    const reqsByVault = {};
    for (const r of state.openReqs) (reqsByVault[r.vaultId] = reqsByVault[r.vaultId] || []).push(r);
    const govByVault = {};
    for (const p of govProposals) {
      const vid = p && p.proposal && p.proposal.vaultId;
      if (vid) (govByVault[vid] = govByVault[vid] || []).push(p);
    }
    const activeOrgs = (orgData.organizations || []).filter((o) => !o.error && o.status !== "ARCHIVED");
    // A filter pointing at a removed/archived organization falls back to All.
    if (state.org !== "all" && state.org !== "unassigned" && !activeOrgs.some((o) => o.orgId === state.org)) state.org = "all";
    const V4_FAMILY = new Set(["policyvault-0.4", "policyvault-0.4.1"]);
    let v4 = (vaults || []).filter((v) => v && V4_FAMILY.has(v.contractVersion));
    if (state.org === "unassigned") v4 = v4.filter((v) => !v.organization || !v.organization.orgId);
    else if (state.org !== "all") v4 = v4.filter((v) => v.organization && v.organization.orgId === state.org);
    const counts = { Active: 0, "Needs Action": 0, Closed: 0, All: v4.length };
    for (const v of v4) { if (isClosed(v)) counts.Closed++; else if (needsAction(v)) counts["Needs Action"]++; else counts.Active++; }
    const shown = v4.filter(matchesFilter).sort((a, b) => (STATUS_RANK[opOf(a)] ?? 5) - (STATUS_RANK[opOf(b)] ?? 5));
    const bar = filterBar(activeOrgs, counts);
    const body = shown.length
      ? shown.map((v) => vaultCard(v, reqsByVault[v.vaultId] || [], govByVault[v.vaultId] || [])).join("")
      : `<div class="empty">No ${state.statusFilter.toLowerCase()} vaults.<div style="margin-top:0.8rem"><button class="primary" id="v4-empty-create">Create Vault</button></div></div>`;
    root.innerHTML = bar + body;
    // wire filter bar
    root.querySelectorAll("[data-status]").forEach((b) => (b.onclick = () => { state.statusFilter = b.dataset.status; render(); }));
    const orgSel = $("v4-org");
    if (orgSel) orgSel.onchange = () => { state.org = orgSel.value; render(); };
    const ec = $("v4-empty-create");
    if (ec) ec.onclick = () => { state.view = "create"; render(); };
    wireVault(root);
    wireOrgAssign(root);
  }

  /* ============ ORGANIZATIONS (off-chain application metadata) ============
   * Rename / Archive / Restore / Delete operate ONLY on local organization
   * metadata: they never change covenant authority, vault state, manifests,
   * or anything on-chain. Delete is blocked while vaults are assigned. */
  async function renderOrgsView(root, stale = () => false) {
    let data;
    try { data = await getJSON("/organizations"); } catch (e) { if (!stale()) root.innerHTML = `<div class="empty">Could not load organizations: ${esc(e.message)}</div>`; return; }
    let vaults = [];
    try { ({ vaults = [] } = await getJSON("/vaults")); } catch { vaults = []; }
    if (stale()) return;
    state.orgData = data;
    const labelOf = new Map((vaults || []).filter(Boolean).map((v) => [v.vaultId, v.label || short(v.vaultId)]));
    const assignments = data.assignments || {};
    const byOrg = {};
    for (const [vid, a] of Object.entries(assignments)) { (byOrg[a.orgId] = byOrg[a.orgId] || []).push(vid); }
    const orgs = (data.organizations || []).filter((o) => !o.error);
    const corrupt = (data.organizations || []).filter((o) => o.error);
    const act = orgs.filter((o) => o.status !== "ARCHIVED");
    const arch = orgs.filter((o) => o.status === "ARCHIVED");
    const unassigned = (vaults || []).filter((v) => v && v.vaultId && !assignments[v.vaultId]).map((v) => v.vaultId);
    // Governance/risk controls per ACTIVE organization (item 3). Best-effort
    // and read-only display when the module or a fetch fails — this view
    // must never block on it (mirrors the corrupt/error handling already
    // used for organization records above).
    const controlsUI = orgControlsUI();
    const controlsByOrg = new Map();
    if (controlsUI) {
      await Promise.all(act.map(async (o) => {
        try { controlsByOrg.set(o.orgId, await controlsUI.fetchControls(o.orgId)); }
        catch { controlsByOrg.set(o.orgId, null); }
      }));
    }
    if (stale()) return;
    const moveSelect = (vid, currentOrgId) =>
      `<select data-orgassign="${esc(vid)}"><option value="">Unassigned</option>` +
      act.map((o) => `<option value="${esc(o.orgId)}"${o.orgId === currentOrgId ? " selected" : ""}>${esc(o.name)}</option>`).join("") +
      `</select>`;
    const orgRow = (o) => {
      const vids = byOrg[o.orgId] || [];
      const archived = o.status === "ARCHIVED";
      const actions = archived
        ? `<button data-orgrestore="${esc(o.orgId)}" data-ver="${o.version}">Restore</button>` +
          `<button class="warn" data-orgdelete="${esc(o.orgId)}" data-ver="${o.version}" data-count="${vids.length}">Delete permanently</button>`
        : `<button data-orgrename="${esc(o.orgId)}" data-ver="${o.version}" data-name="${esc(o.name)}">Rename</button>` +
          `<button data-orgarchive="${esc(o.orgId)}" data-ver="${o.version}" data-name="${esc(o.name)}">Archive</button>` +
          `<button class="warn" data-orgdelete="${esc(o.orgId)}" data-ver="${o.version}" data-count="${vids.length}">Delete permanently</button>`;
      const vaultLines = (vids.length
        ? vids.map((vid) => `<div class="evt">${esc(labelOf.get(vid) || short(vid))} ${moveSelect(vid, o.orgId)}</div>`).join("")
        : `<div class="hint">No vaults assigned.</div>`) +
        (!archived && unassigned.length
          ? `<div class="org-assign">Assign vault <select data-orgadd="${esc(o.orgId)}"><option value="" selected>choose…</option>` +
            unassigned.map((vid) => `<option value="${esc(vid)}">${esc(labelOf.get(vid) || short(vid))}</option>`).join("") + `</select></div>`
          : "");
      // Members / roles — ORGANIZATION APPLICATION METADATA ONLY (§ org-role
      // separation): these are directory labels; they never grant or modify
      // Kaspa covenant authority, and an organization "approver" is NOT a
      // covenant approver (covenant approvers are set on the vault itself).
      const memberLines = (o.members || []).length
        ? o.members.map((m) =>
            `<div class="evt">${esc(m.displayName)}${m.address ? ` · <span class="mono">${esc(short(m.address))}</span>` : " · contact-only"} · ` +
            m.roles.map((r) => `<span class="rolechip">${esc(r)} (org role)</span>`).join("") +
            `${m.status === "INACTIVE" ? ` <span class="badge PAUSED">INACTIVE</span>` : ""}` +
            (!archived ? ` <button class="warn" data-rmmember="${esc(o.orgId)}" data-member="${esc(m.memberId)}" data-ver="${o.version}">Remove</button>` : "") +
            `</div>`).join("")
        : `<div class="hint">No members recorded.</div>`;
      const memberForm = !archived
        ? `<form class="cform" data-addmember="${esc(o.orgId)}" data-ver="${o.version}" autocomplete="off" style="margin-top:0.5rem">` +
          `<div><label>Display name</label><input name="displayName" placeholder="Alice" /></div>` +
          `<div><label>Wallet address (optional)</label><input name="address" class="mono" placeholder="${addrExample()}" /></div>` +
          `<div class="full"><label>Organization roles (application labels — never on-chain authority)</label>` +
          ((data.roleLabels || []).map((r) => `<label style="text-transform:none;display:inline-block;margin-right:0.8rem"><input type="checkbox" name="role" value="${esc(r)}" style="width:auto" /> ${esc(r)}</label>`).join("")) +
          `</div>` +
          `<div class="full"><button type="submit">Add member</button></div></form>`
        : "";
      const membersBlock =
        `<details class="adv"><summary>Members &amp; roles (organization metadata)</summary>` +
        `<div class="hint">Organization roles and assignments are application metadata. They do not grant or modify Kaspa covenant authority. An organization "approver" is NOT a v0.4.1 covenant approver — covenant approvers are set on the vault itself.</div>` +
        memberLines + memberForm + `</details>`;
      // Governance/risk controls (item 3): CAS-versioned hosted-workflow
      // configuration. Never rendered for an archived organization (restore
      // it first) or when the module/fetch failed (read-only notice).
      const controlsBlock = archived
        ? ""
        : `<details class="adv"><summary>Governance &amp; risk controls</summary>` +
          (controlsUI
            ? controlsByOrg.get(o.orgId) !== null && controlsByOrg.get(o.orgId) !== undefined
              ? controlsUI.renderControlsFormHtml(controlsByOrg.get(o.orgId))
              : `<div class="hint">Controls could not be loaded for this organization.</div>`
            : `<div class="hint">The controls editor module is not loaded on this page.</div>`) +
          `</details>`;
      return (
        `<div class="panel"><div class="vault-head"><span class="vault-title">${esc(o.name)}</span>` +
        `<span><span class="badge ${archived ? "PAUSED" : "ACTIVE"}">${esc(o.status)}</span></span></div>` +
        `<div class="kv-line">${vids.length} vault${vids.length === 1 ? "" : "s"} assigned · ${(o.members || []).length} member${(o.members || []).length === 1 ? "" : "s"} · metadata version ${o.version}</div>` +
        `<div class="actions">${actions}</div>` +
        `<details class="adv"><summary>Assigned vaults</summary>${vaultLines}</details>` +
        membersBlock + controlsBlock + `</div>`
      );
    };
    root.innerHTML =
      `<div class="panel"><h3 style="margin-top:0">Organizations</h3>` +
      `<div class="hint">Organizations are off-chain application metadata: they group vaults for display and grant NO Kaspa covenant authority. Archive hides an organization from normal selectors (recoverable); Delete is permanent and only possible once no vaults are assigned.</div>` +
      `<div class="org-assign" style="margin-top:0.7rem"><input id="v4-org-new-name" placeholder="New organization name" style="max-width:280px" /> <button id="v4-org-create-btn" class="primary">Create organization</button></div></div>` +
      (act.length ? act.map(orgRow).join("") : `<div class="empty">No active organizations.</div>`) +
      (arch.length ? `<h3 style="margin:1.2rem 0 0.6rem">Archived organizations</h3>` + arch.map(orgRow).join("") : "") +
      (corrupt.length ? `<div class="panel"><b>Metadata problems:</b> ${corrupt.map((c) => `${esc(c.orgId)} — ${esc(c.error)}`).join("; ")}</div>` : "");
    wireOrgs(root);
    wireOrgAssign(root);
  }

  function wireOrgs(root) {
    // Members / roles (organization application metadata only).
    root.querySelectorAll("[data-addmember]").forEach((f) => f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const displayName = (f.querySelector('[name="displayName"]')?.value ?? "").trim();
      const address = (f.querySelector('[name="address"]')?.value ?? "").trim();
      const roles = [...f.querySelectorAll('[name="role"]:checked')].map((c) => c.value);
      if (!displayName) { note("Enter a display name for the member.", "bad"); return; }
      if (!roles.length) { note("Choose at least one organization role label.", "bad"); return; }
      try {
        await postJSON(`/organizations/${f.getAttribute("data-addmember")}/members`, { displayName, ...(address ? { address } : {}), roles, expectedVersion: Number(f.getAttribute("data-ver")) });
        note("Member added (organization metadata only — no covenant authority granted).", "good");
      } catch (err) { note(`Add member failed: ${err.code || ""} ${err.message}`, "bad"); }
      render();
    }));
    root.querySelectorAll("[data-rmmember]").forEach((b) => (b.onclick = async () => {
      if (!window.confirm("Remove this member label? This changes organization metadata only.")) return;
      try {
        await postJSON(`/organizations/${b.getAttribute("data-rmmember")}/members/${b.getAttribute("data-member")}/remove`, { expectedVersion: Number(b.getAttribute("data-ver")) });
        note("Member removed (metadata only).", "good");
      } catch (err) { note(`Remove member failed: ${err.code || ""} ${err.message}`, "bad"); }
      render();
    }));
    // Governance/risk controls (item 3): CAS-versioned save. A
    // VERSION_CONFLICT is NEVER retried with the stale edit — it is
    // surfaced as reload-and-retry (this org's card re-renders from fresh
    // server state; the admin re-applies their edit against the new
    // version, never a blind overwrite).
    root.querySelectorAll("[data-controls-form]").forEach((f) => f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const cu = orgControlsUI();
      if (!cu) { note("The controls editor module failed to load.", "bad"); return; }
      const orgId = f.getAttribute("data-org-id");
      const expectedVersion = Number(f.getAttribute("data-org-version"));
      const values = {
        approverAddresses: f.querySelector('[name="approverAddresses"]')?.value ?? "",
        m: f.querySelector('[name="m"]')?.value ?? "",
        delayHours: f.querySelector('[name="delayHours"]')?.value ?? "",
        onAdapterError: f.querySelector('[name="onAdapterError"]')?.value ?? "",
        onEmpty: f.querySelector('[name="onEmpty"]')?.value ?? "",
        timeoutMs: f.querySelector('[name="timeoutMs"]')?.value ?? "",
        reviewRequired: !!f.querySelector('[name="reviewRequired"]')?.checked,
        adaptersJson: f.querySelector('[name="adaptersJson"]')?.value ?? ""
      };
      const submitBtn = f.querySelector('button[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;
      try {
        await cu.saveControls(orgId, values, { expectedVersion });
        note("Governance & risk controls saved. This is hosted coordination only — it never grants or modifies Kaspa covenant authority.", "good");
      } catch (err) {
        if (err.versionConflict) {
          note("These controls changed since you loaded this form — reloading the current version. Re-apply your edit and save again.", "warn");
        } else {
          note(`Save controls failed: ${err.code || ""} ${err.message}`, "bad");
          if (submitBtn) submitBtn.disabled = false;
          return;
        }
      }
      render(); // reload-and-retry: always re-fetches fresh controls, never keeps the stale form
    }));
    // Assign a currently-unassigned vault to this organization (metadata only).
    root.querySelectorAll("[data-orgadd]").forEach((sel) => (sel.onchange = async () => {
      if (!sel.value) return;
      try {
        const fresh = await getJSON("/organizations");
        await postJSON(`/organizations/${sel.getAttribute("data-orgadd")}/vaults`, { vaultId: sel.value, expectedVersion: fresh.assignmentsVersion ?? 0 });
        note("Vault assigned (application metadata only).", "good");
      } catch (e) { note(`Assign failed: ${e.code || ""} ${e.message}`, "bad"); }
      render();
    }));
    const btn = $("v4-org-create-btn");
    if (btn) btn.onclick = async () => {
      const name = ($("v4-org-new-name")?.value ?? "").trim();
      if (!name) { note("Enter a name for the new organization.", "bad"); return; }
      try { await postJSON("/organizations", { name }); note(`Organization "${name}" created.`, "good"); render(); }
      catch (e) { note(`Create organization failed: ${e.code || ""} ${e.message}`, "bad"); }
    };
    root.querySelectorAll("[data-orgrename]").forEach((b) => (b.onclick = async () => {
      const name = window.prompt("New organization name:", b.getAttribute("data-name") || "");
      if (name === null || !name.trim()) return;
      try {
        await postJSON(`/organizations/${b.getAttribute("data-orgrename")}/rename`, { name: name.trim(), expectedVersion: Number(b.getAttribute("data-ver")) });
        note("Organization renamed (metadata only — vault associations and on-chain state unchanged).", "good");
      } catch (e) { note(`Rename failed: ${e.code || ""} ${e.message}`, "bad"); }
      render();
    }));
    root.querySelectorAll("[data-orgarchive]").forEach((b) => (b.onclick = async () => {
      if (!window.confirm(`Archive "${b.getAttribute("data-name")}"?\n\nArchiving changes only local organization visibility: the organization disappears from normal selectors but stays recoverable, vaults keep their association, and nothing on-chain changes.`)) return;
      try {
        await postJSON(`/organizations/${b.getAttribute("data-orgarchive")}/archive`, { expectedVersion: Number(b.getAttribute("data-ver")) });
        note("Organization archived — restore it any time from this view.", "good");
      } catch (e) { note(`Archive failed: ${e.code || ""} ${e.message}`, "bad"); }
      render();
    }));
    root.querySelectorAll("[data-orgrestore]").forEach((b) => (b.onclick = async () => {
      try {
        await postJSON(`/organizations/${b.getAttribute("data-orgrestore")}/restore`, { expectedVersion: Number(b.getAttribute("data-ver")) });
        note("Organization restored to active.", "good");
      } catch (e) { note(`Restore failed: ${e.code || ""} ${e.message}`, "bad"); }
      render();
    }));
    root.querySelectorAll("[data-orgdelete]").forEach((b) => (b.onclick = async () => {
      const count = Number(b.getAttribute("data-count") || "0");
      if (count > 0) {
        note(`Cannot delete: ${count} vault${count === 1 ? "" : "s"} still assigned. Move them to another organization or set them to Unassigned first (open "Assigned vaults" on the organization).`, "warn");
        return;
      }
      if (!window.confirm("Permanently delete this organization?\n\nOnly local metadata is removed. Vaults are never deleted, recovered, closed, or altered by this.")) return;
      try {
        await postJSON(`/organizations/${b.getAttribute("data-orgdelete")}/delete`, { expectedVersion: Number(b.getAttribute("data-ver")) });
        note("Organization deleted (metadata only).", "good");
      } catch (e) {
        if (e.code === "ORG_NOT_EMPTY") note(`Cannot delete: vaults are still assigned. Move them to another organization or set them to Unassigned first.`, "warn");
        else note(`Delete failed: ${e.code || ""} ${e.message}`, "bad");
      }
      render();
    }));
  }

  /* Shared wiring for every organization-assignment <select> (vault cards +
   * the Organizations view). Assignment is metadata-only; the current
   * assignments version is re-fetched at action time so a concurrent change
   * fails loudly (VERSION_CONFLICT) instead of overwriting. */
  function wireOrgAssign(root) {
    root.querySelectorAll("[data-orgassign]").forEach((sel) => (sel.onchange = async () => {
      const vaultId = sel.getAttribute("data-orgassign");
      try {
        const fresh = await getJSON("/organizations");
        const ver = fresh.assignmentsVersion ?? 0;
        const cur = (fresh.assignments || {})[vaultId];
        if (sel.value === "") {
          if (!cur) { render(); return; }
          await postJSON(`/organizations/${cur.orgId}/vaults/${vaultId}/unassign`, { expectedVersion: ver });
          note("Vault set to Unassigned (application metadata only).", "good");
        } else {
          await postJSON(`/organizations/${sel.value}/vaults`, { vaultId, expectedVersion: ver });
          note("Vault organization updated (application metadata only).", "good");
        }
      } catch (e) { note(`Organization change failed: ${e.code || ""} ${e.message}`, "bad"); }
      render();
    }));
  }

  /* ===================== ACTIVITY (first-class audit surface) =============
   * Durable audit events, clearly separated into CHAIN events (transactions
   * verified against Kaspa) and METADATA events (off-chain application data
   * — organizations/assignments — which are NEVER chain-enforced). */
  async function renderActivityView(root, stale = () => false) {
    let events = [];
    try { ({ events = [] } = await getJSON("/audit?limit=300")); } catch (e) { if (!stale()) root.innerHTML = `<div class="empty">Could not load activity: ${esc(e.message)}</div>`; return; }
    if (stale()) return;
    // Event-type label mirrors the server's own per-org audit mapping
    // (server/src/api.js eventTypeOf): governance/risk/intent are hosted-
    // coordination records, NOT verified chain transactions, and must
    // never be badged "CHAIN" — that label is reserved for actual
    // transaction-pipeline audit rows (the untyped default here).
    const EVENT_TYPE_LABEL = { metadata: "METADATA", governance: "GOVERNANCE", risk: "RISK", intent: "INTENT" };
    const row = (e) => {
      const label = EVENT_TYPE_LABEL[e.kind];
      const isChain = !label;
      const tag = `<span class="tag ${isChain ? "chain" : "meta"}">${label || "CHAIN"}</span>`;
      const verified = isChain && /verified|advanced|recovered|created/i.test(e.action || "") ? ` <span class="badge ACTIVE">CHAIN_VERIFIED</span>` : "";
      return (
        `<div class="evt">${tag} <b>${esc(e.action || "event")}</b>` +
        (e.vaultId ? ` · vault <span class="mono">${esc(short(e.vaultId))}</span>` : "") +
        (e.orgId ? ` · org <span class="mono">${esc(String(e.orgId).slice(0, 8))}</span>` : "") +
        (e.txId ? ` · tx <span class="mono">${esc(short(e.txId))}</span>${verified}` : "") +
        (e.detail ? ` · ${esc(String(e.detail).slice(0, 120))}` : "") +
        ` <span class="hint" style="display:inline">${esc(e.at || e.timestamp || "")}</span></div>`
      );
    };
    root.innerHTML =
      `<div class="panel"><h3 style="margin-top:0">Activity</h3>` +
      `<div class="hint">CHAIN events are transactions verified against Kaspa consensus. GOVERNANCE, RISK, and INTENT events are hosted-workflow coordination and evidence — like METADATA (organizations, assignments), they are never chain-enforced and grant no covenant authority on their own.</div></div>` +
      `<div class="panel">${events.length ? events.map(row).join("") : `<div class="empty">No activity yet.</div>`}</div>`;
  }

  /* ===================== SUPPORT (voluntary donations) ====================
   * The donation address comes ONLY from the server's validated configuration
   * (GET /support) — never from the connected wallet, a vault owner, or any
   * key material. PolicyVault is free to use; support is voluntary. */
  const SUPPORT_EMAIL = "zapsoblige@gmail.com"; // intentionally public contact
  async function renderSupportView(root, stale = () => false) {
    let data = null;
    try { data = await getJSON("/support"); } catch (e) { if (!stale()) root.innerHTML = `<div class="empty">Could not load support info: ${esc(e.message)}</div>`; return; }
    if (stale()) return;
    const donation = data && data.support && data.support.donation;
    root.innerHTML =
      `<div class="panel"><h3 style="margin-top:0">Support PolicyVault</h3>` +
      `<p>PolicyVault is <b>free to use</b> — no subscriptions, no fees, no paid features. ` +
      `Voluntary donations help support continued development and hosting.</p>` +
      (donation
        ? `<div class="k" style="text-transform:uppercase;font-size:0.72rem;color:var(--muted)">Kaspa donation address (mainnet)</div>` +
          `<div class="donate-box"><span class="mono addr" id="v4-donate-addr">${esc(donation.address)}</span>` +
          `<button id="v4-donate-copy" class="primary">Copy address</button></div>` +
          `<div class="hint" style="margin-top:0.6rem">This is the project owner's public receiving address, configured server-side and validated as a mainnet Kaspa address. It never changes with your connected wallet.</div>`
        : `<div class="hint">Support is not configured in this instance${data && data.reason ? ` (${esc(data.reason)})` : ""}.</div>`) +
      `</div>` +
      // Intentionally public project contact address (owner directive). A
      // static constant — never derived from the wallet or runtime state, and
      // separate from the donation method above.
      `<div class="panel"><h3 style="margin-top:0">Contact / Support</h3>` +
      `<div class="donate-box"><span class="mono addr" id="v4-support-email">${SUPPORT_EMAIL}</span>` +
      `<button id="v4-support-email-copy" class="primary">Copy email</button>` +
      `<a class="btnlink" id="v4-support-email-send" href="mailto:${SUPPORT_EMAIL}">Send email</a></div>` +
      `<div class="hint" style="margin-top:0.6rem">Questions, problems, or security reports — email is the support channel. Never include seed phrases, private keys, or recovery material in any message.</div>` +
      `</div>`;
    const btn = $("v4-donate-copy");
    if (btn && donation) btn.onclick = async () => {
      try {
        if (window.navigator.clipboard && window.navigator.clipboard.writeText) await window.navigator.clipboard.writeText(donation.address);
        note("Donation address copied. Thank you!", "good");
      } catch {
        note("Could not access the clipboard — copy the address text directly.", "warn");
      }
    };
    const mailBtn = $("v4-support-email-copy");
    if (mailBtn) mailBtn.onclick = async () => {
      try {
        if (window.navigator.clipboard && window.navigator.clipboard.writeText) await window.navigator.clipboard.writeText(SUPPORT_EMAIL);
        note("Support email copied.", "good");
      } catch {
        note("Could not access the clipboard — copy the email text directly.", "warn");
      }
    };
  }

  const promptKas = (m) => { const v = window.prompt(m); if (v === null) return null; return v.trim() || null; };

  /* ---- hosted agent suspend/unsuspend (fullscale surface 21 web
   * composition; POST /vaults/:id/agent-suspensions) ----
   * COORDINATION CONTROL ONLY — NEVER A COVENANT CONTROL. The confirm
   * copy states it, the state banner renders the server's
   * NOT_COVENANT_NOTICE verbatim, and the covenant controls (Pause /
   * Remove agent) stay rendered alongside — a suspension never replaces
   * them. The flip is CAS-guarded with the loaded record's version
   * (VERSION_CONFLICT reloads); with the state UNKNOWN the UI refuses
   * locally (fail closed) instead of flipping blind. Foreign vaults /
   * unauthorized principals surface the server's 403/404 verbatim. */
  async function suspendUpdate(vaultId, { op, agentPk, allAgents }) {
    const current = (state.suspByVault && state.suspByVault[vaultId]) || null;
    if (!current || current.error) {
      note("Hosted suspension state is unknown for this vault — reload before changing it (failing closed).", "bad");
      return;
    }
    const scope = allAgents === true ? "ALL agents of this vault" : `agent ${short(agentPk)}`;
    const okConfirm =
      op === "suspend"
        ? window.confirm(
            `Suspend ${scope} at the HOSTED layer?\n\n` +
              `Coordination control only — NOT a covenant control. This makes the PolicyVault server refuse NEW build/finalize/submit requests for ${scope} instantly (free, reversible). ` +
              `It CANNOT stop a malicious holder of the delegate key submitting transactions directly to a Kaspa node — only covenant-enforced controls (Pause, Remove agent, Close & recover) bind that adversary on-chain.\n\n` +
              `For covenant-enforced protection, use Pause or Remove agent (instead, or as well).`
          )
        : window.confirm(
            `Lift the hosted suspension for ${scope}?\n\nThis re-opens THIS server's pipeline for ${scope}; it changes nothing on-chain.`
          );
    if (!okConfirm) return;
    try {
      const body = { op, expectedVersion: current.version, ...(allAgents === true ? { allAgents: true } : { agentPk }) };
      const { suspensions } = await postJSON(`/vaults/${vaultId}/agent-suspensions`, body);
      if (state.suspByVault) state.suspByVault[vaultId] = suspensions;
      note(`Hosted suspension updated (version ${suspensions && suspensions.version}). Coordination control only — never a covenant control; for on-chain protection use Pause or Remove agent.`, "good");
    } catch (e) {
      if (e && e.code === "VERSION_CONFLICT") {
        note("Suspension state changed concurrently — reloading; retry the change against the fresh state.", "warn");
      } else {
        note(`Suspension update failed: ${e.code || ""} ${e.message}`, "bad");
      }
    }
    render();
  }

  function wireVault(root) {
    root.querySelectorAll("[data-spend]").forEach((b) => (b.onclick = async () => {
      const agentPk = b.getAttribute("data-spend");
      const recipient = window.prompt("Recipient wallet address (must be in this agent's allowlist):");
      const payKas = promptKas("Spend amount (KAS):");
      if (!recipient || !payKas) return;
      let recipientX;
      try { recipientX = await resolveXOnly(recipient.trim()); } catch (e) { note(`Recipient address invalid: ${e.message}`, "bad"); return; }
      const payAmountSompi = kasToSompiClient(payKas);
      if (payAmountSompi === null) { note("Invalid spend amount.", "bad"); return; }
      const vaultId = b.closest("[data-vault]").getAttribute("data-vault");
      runFlow(vaultId, "agentSpend", { agentPk, recipient: recipientX, payAmountSompi }, "Sign spend");
    }));
    // ---- pending approval-request actions (server-state-driven) ----
    const openReq = (id) => (state.openReqs || []).find((r) => r.requestId === id);
    // RESUMED flows (approver review / agent-sign-after-approvals): the
    // original form context is gone, so the intent is reconstructed from the
    // DURABLE server request — verification proves the frozen bytes do
    // exactly what the displayed request claims, against THIS browser's own
    // vault knowledge (the verify layer states this provenance in its notes).
    root.querySelectorAll("[data-approvereq]").forEach((b) => (b.onclick = () => {
      const req = openReq(b.getAttribute("data-approvereq"));
      if (!req) { note("Request no longer pending — refreshing.", "warn"); render(); return; }
      const verification = verifyForSigning({ request: req, vaultId: req.vaultId, role: "approver" });
      reviewModal(req.review, () => approve(req, verification), "Approve", undefined, verification);
    }));
    root.querySelectorAll("[data-agentsign]").forEach((b) => (b.onclick = () => {
      const req = openReq(b.getAttribute("data-agentsign"));
      if (!req) { note("Request no longer pending — refreshing.", "warn"); render(); return; }
      const verification = verifyForSigning({ request: req, vaultId: req.vaultId, role: "agent" });
      reviewModal(req.review, () => completeRequestFlow(req, req.action, verification), "Sign spend", undefined, verification);
    }));
    root.querySelectorAll("[data-cancelreq]").forEach((b) => (b.onclick = async () => {
      if (!window.confirm("Cancel this approval request?\n\nCollected approvals are discarded and nothing is broadcast. The vault itself is unaffected.")) return;
      try {
        await postJSON(`/wallet/v4/requests/${b.getAttribute("data-cancelreq")}/reject`, {});
        note("Approval request cancelled.", "good");
      } catch (e) { note(`Cancel failed: ${e.code || ""} ${e.message}`, "bad"); }
      render();
    }));
    // Open governance proposal cards (item 1 persistent surface): opens the
    // SAME ceremony modal the reactive GOVERNANCE_PROPOSAL_REQUIRED path
    // uses, fetched fresh — action/params to retry are recovered from the
    // proposal's own stored content (see openGovernanceCeremony).
    root.querySelectorAll("[data-govopen]").forEach((b) => (b.onclick = () => {
      openGovernanceCeremony({ proposalId: b.getAttribute("data-govopen") });
    }));
    const vid = (b) => b.closest("[data-vault]").getAttribute("data-vault");
    const kasParam = async (b, prompt, key, action, label) => {
      const kas = promptKas(prompt); if (!kas) return;
      const sompi = kasToSompiClient(kas); if (sompi === null) { note("Invalid amount.", "bad"); return; }
      const p = await withFuel({ [key]: sompi }); if (p) runFlow(vid(b), action, p, label);
    };
    root.querySelectorAll("[data-pause]").forEach((b) => (b.onclick = async () => { const p = await withFuel({}); if (p) runFlow(vid(b), "ownerPause", p, "Sign pause"); }));
    root.querySelectorAll("[data-unpause]").forEach((b) => (b.onclick = async () => { const p = await withFuel({}); if (p) runFlow(vid(b), "ownerUnpause", p, "Sign unpause"); }));
    // ---- hosted agent suspend/unsuspend (surface 21; coordination-only) ----
    root.querySelectorAll("[data-suspend]").forEach((b) => (b.onclick = () => suspendUpdate(vid(b), { op: "suspend", agentPk: b.getAttribute("data-suspend") })));
    root.querySelectorAll("[data-unsuspend]").forEach((b) => (b.onclick = () => suspendUpdate(vid(b), { op: "unsuspend", agentPk: b.getAttribute("data-unsuspend") })));
    root.querySelectorAll("[data-suspendall]").forEach((b) => (b.onclick = () => suspendUpdate(b.getAttribute("data-suspendall"), { op: "suspend", allAgents: true })));
    root.querySelectorAll("[data-unsuspendall]").forEach((b) => (b.onclick = () => suspendUpdate(b.getAttribute("data-unsuspendall"), { op: "unsuspend", allAgents: true })));
    root.querySelectorAll("[data-topup]").forEach((b) => (b.onclick = () => kasParam(b, "Top up principal (KAS):", "topUpAmountSompi", "ownerTopUp", "Sign top-up")));
    root.querySelectorAll("[data-topupreserve]").forEach((b) => (b.onclick = () => kasParam(b, "Top up fee reserve (KAS):", "topUpReserveAmountSompi", "ownerTopUpReserve", "Sign reserve top-up")));
    root.querySelectorAll("[data-recover]").forEach((b) => (b.onclick = async () => { if (!window.confirm("Close and recover this vault? This is terminal.")) return; const p = await withFuel({}); if (p) runFlow(vid(b), "ownerRecover", p, "Sign recovery"); }));
    root.querySelectorAll("[data-remove]").forEach((b) => (b.onclick = async () => { const p = await withFuel({ agentPk: b.getAttribute("data-remove") }); if (p) runFlow(vid(b), "removeAgent", p, "Sign agent removal"); }));
    root.querySelectorAll("[data-verify]").forEach((b) => (b.onclick = async () => {
      try { const r = await postJSON(`/vaults/${vid(b)}/reconcile`, {}); note(`Verify: ${r.reconcile.status}`, "good"); render(); } catch (e) { note(`Verify failed: ${e.message}`, "bad"); }
    }));
    // add/re-policy/rotate agent: friendly prompts (addresses + KAS), resolved to
    // the canonical agent object client-side (the OWNER authorizes it by signing);
    // periodStartDaa comes from the authoritative node DAA, periodSpent = 0.
    const agentFromPrompts = async () => {
      try {
        const agentAddress = window.prompt("Agent wallet address:"); if (!agentAddress) return null;
        const maxKas = promptKas("Maximum per transaction (KAS):"); if (!maxKas) return null;
        const budgetKas = promptKas("Budget per period (KAS):"); if (!budgetKas) return null;
        const recips = window.prompt("Allowed recipient wallet addresses (comma-separated):"); if (!recips) return null;
        const thresholdKas = promptKas("Require approval above (KAS):") || "0";
        const maxPerSpend = kasToSompiClient(maxKas), periodBudget = kasToSompiClient(budgetKas), approvalThreshold = kasToSompiClient(thresholdKas);
        if (maxPerSpend === null || periodBudget === null || approvalThreshold === null) { note("Invalid KAS amount.", "bad"); return null; }
        const agentPk = await resolveXOnly(agentAddress.trim());
        const recipients = [];
        for (const r of recips.split(",").map((s) => s.trim()).filter(Boolean)) recipients.push(await resolveXOnly(r));
        if (!recipients.length) { note("At least one recipient address is required.", "bad"); return null; }
        const { virtualDaaScore } = await getJSON("/network/status");
        return { agentPk, maxPerSpend, periodBudget, periodLengthDaa: "864000", periodStartDaa: String(virtualDaaScore), periodSpent: "0", approvalThreshold, agentMaxFeePerTx: "10000000", recipients };
      } catch (e) { note(`Agent input invalid: ${e.message}`, "bad"); return null; }
    };
    root.querySelectorAll("[data-addagent]").forEach((b) => (b.onclick = async () => { const a = await agentFromPrompts(); if (!a) return; const p = await withFuel({ agent: a }); if (p) runFlow(vid(b), "addAgent", p, "Sign add-agent"); }));
    root.querySelectorAll("[data-repolicy]").forEach((b) => (b.onclick = async () => { const a = await agentFromPrompts(); if (!a) return; const p = await withFuel({ agentPk: b.getAttribute("data-repolicy"), agent: a }); if (p) runFlow(vid(b), "rePolicyAgent", p, "Sign re-policy"); }));
    root.querySelectorAll("[data-rotate]").forEach((b) => (b.onclick = async () => { const a = await agentFromPrompts(); if (!a) return; const p = await withFuel({ agentPk: b.getAttribute("data-rotate"), agent: a }); if (p) runFlow(vid(b), "rotateAgent", p, "Sign key rotation"); }));
    root.querySelectorAll("[data-setapprovers]").forEach((b) => (b.onclick = async () => {
      try {
        const raw = window.prompt("Approver wallet addresses (comma-separated):"); if (!raw) return;
        const approvers = [];
        for (const a of raw.split(",").map((s) => s.trim()).filter(Boolean)) approvers.push(await resolveXOnly(a));
        const approvalM = promptKas("Required approvals (M):") || String(approvers.length);
        const p = await withFuel({ newApprovers: { approvers, approvalM } });
        if (p) runFlow(vid(b), "ownerSetApprovers", p, "Sign set-approvers");
      } catch (e) { note(`Approver input invalid: ${e.message}`, "bad"); }
    }));
  }

  /* Client-side KAS→sompi is display convenience only; the SERVER re-derives and
   * validates every consensus-visible amount. Returns a digit string or null. */
  function kasToSompiClient(kas) {
    const s = String(kas).trim();
    if (!/^\d+(\.\d{1,8})?$/.test(s)) return null;
    const [intPart, frac = ""] = s.split(".");
    const sompi = BigInt(intPart) * 100000000n + BigInt((frac + "00000000").slice(0, 8));
    return sompi > 0n ? sompi.toString() : (sompi === 0n ? "0" : null);
  }

  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".v4-tab").forEach((b) => (b.onclick = () => { state.view = b.dataset.view; render(); }));
    // Server-authoritative network label (Gate R: testnet-10 or mainnet) —
    // presentation only (address-example placeholders); every real network
    // check is enforced by the session gate and the server.
    getJSON("/health").then((h) => { state.serverNetwork = h.networkId || null; }).catch(() => { state.serverNetwork = null; });
    // ONE-TIME delegated wiring for create-form row controls, attached to the
    // persistent #v4-root exactly once (never per render): re-renders can no
    // longer stack duplicate listeners, so one click adds exactly one row.
    const root = $("v4-root");
    if (root) root.addEventListener("click", handleCreateRowClick);
    const supportLink = document.getElementById("footer-support-link");
    if (supportLink) supportLink.onclick = (e) => { e.preventDefault(); state.view = "support"; render(); window.scrollTo(0, 0); };
    // Consume the ONE canonical wallet session. There is no v0.4.1-specific
    // connect control or provider; the global Wallet panel owns the connection.
    // subscribe() fires immediately with the current snapshot, driving render.
    if (window.PolicyVaultWalletSession) window.PolicyVaultWalletSession.subscribe(updateWallet);
    else render();
  });

  // _walletSign / _reviewModal / _verifyForSigning / _runFlow /
  // _openGovernanceCeremony / _openRiskHold are exposed for the BROWSER
  // test layer only (they let the regression suites prove the
  // canonical-signInputs guard and the browser-verification gate refuse
  // BEFORE any provider call, that a refused verification renders the
  // DO-NOT-SIGN modal without a signing action, and that a
  // GOVERNANCE_PROPOSAL_REQUIRED / RISK_REVIEW_REQUIRED / RISK_DENIED
  // refusal from runFlow is handed to the ceremony/hold UI rather than
  // silently softened or bypassed); production code never uses them.
  window.PolicyVaultV4 = {
    render,
    _state: state,
    _session: session,
    _walletSign: walletSign,
    _reviewModal: reviewModal,
    _verifyForSigning: verifyForSigning,
    _runFlow: runFlow,
    _openGovernanceCeremony: openGovernanceCeremony,
    _openRiskHold: openRiskHold,
    _suspendUpdate: suspendUpdate
  };
})();
