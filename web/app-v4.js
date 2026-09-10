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
  const state = { address: null, xonly: null, network: null, serverNetwork: null, nodeNetwork: null, ready: false, provider: null, auth: null, view: "vaults", statusFilter: "Active", org: "all", renderedOnce: false, orgData: null, openReqs: [], vaultsById: {}, cache: {} };
  /* ---- retained-state identity binding (UX responsiveness pass) ----
   * Views retain their last-good fetched data so returning to a tab paints
   * IMMEDIATELY while an authoritative background refresh runs. Every
   * retained entry is bound to this identity epoch — wallet address,
   * wallet network, and hosted-session status — and a change of ANY of
   * them (wallet switch, account switch, network switch, sign-in,
   * sign-out/expiry) discards every entry and every shared in-flight GET:
   * an older identity's data can never be painted for, or overwritten
   * onto, a newer one. */
  const dataEpoch = () => [state.address || "", state.network || "", state.auth || ""].join("|");
  const signedOutHosted = () => state.auth && state.auth !== "AUTHENTICATED" && state.auth !== "DISABLED";
  const isAuthRefusal = (e) => e && (e.code === "SESSION_INVALID" || e.code === "AUTH_REQUIRED" || e.code === "SESSION_EXPIRED");
  function dropRetainedState() {
    state.cache = {};
    inflightGets.clear();
  }
  const session = () => (window.PolicyVaultWalletSession ? window.PolicyVaultWalletSession.active() : { connected: false, ready: false });
  // Server-derived network display label (never a hardcoded network name):
  // state.serverNetwork is set from GET /health at DOMContentLoaded (below)
  // and is the ONLY source of truth for what network this build talks to.
  // Falls back to a neutral phrase before that resolves — never guesses
  // "testnet-10". Display-only; every real network check stays on the
  // session gate (state.ready) and the server.
  // ORDER MATTERS (TRACK 11): state.nodeNetwork is the NODE's own reported
  // identity from /network/status — the exact value the signing gate
  // compares against and the value the top banner derives from — so it is
  // preferred. state.serverNetwork (/health) is the fallback for the moment
  // before the node probe resolves, and a neutral phrase is the last
  // resort: this helper never names a network it was not told.
  const networkLabel = () => state.nodeNetwork || state.serverNetwork || "the configured network";

  /* ---- WHY signing is disabled (TRACK 11, finding N1) ----
   * Signing fails closed when the wallet's network and the NODE-reported
   * network are not the same known value — and that includes the case
   * where PolicyVault could not read its node's network at all. Both used
   * to render the same sentence, "switch KasWare to the configured
   * network", which sends a user to fiddle with their wallet over a
   * backend/node problem their wallet cannot fix. This is the honest
   * second case; it mirrors the top banner's fail-closed UNKNOWN and
   * changes no gate. */
  const notReadyNodeUnknownHtml = () =>
    `<b>Network status unknown — signing is disabled.</b> PolicyVault has not confirmed which Kaspa network its node is on, ` +
    `so it refuses to sign rather than guess. <span class="hint" style="display:inline">This is not a problem with your wallet — ` +
    `changing networks in KasWare will not clear it. The banner at the top of the page retries on its own; if it stays unknown, ` +
    `the server's Kaspa node is unreachable.</span>`;

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
  /* In-flight GET de-duplication (mirrors app.js): concurrent identical
   * GETs share ONE request; entries clear on settlement, so nothing is
   * ever served from a response cache. Mutations (postJSON) are NEVER
   * deduplicated. The map is flushed on every identity-epoch change. */
  const inflightGets = new Map();
  async function getJSON(p) {
    if (inflightGets.has(p)) return inflightGets.get(p);
    const req = (async () => {
      const r = await fetch(API + p);
      const j = await r.json();
      if (!r.ok) throw apiError(j, r);
      return j;
    })();
    inflightGets.set(p, req);
    try {
      return await req;
    } finally {
      inflightGets.delete(p);
    }
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
    // Only a notice that belongs to the root setup wizard (its progress,
    // validation or BUILD refusal — written through noteRootWizard) is cleared
    // when the wizard is cancelled or its view is left. A newer notice
    // (especially a pending/unknown outcome) always replaces this scope.
    state.rootBuildRefusal = false;
    const el = $("v4-notice");
    if (!el) return;
    el.textContent = msg;
    el.className = "panel " + (cls || "");
    el.style.display = msg ? "block" : "none";
  }

  /* ---- REFUSAL RENDERING (TRACK 11) ----
   * A refusal used to reach the user as "<action> rejected: CODE <server
   * message>" — a machine code in a red bar, with no statement of what it
   * means or what to do next. noteRefusal() keeps that exact summary line
   * (it is what a support report should quote, and it is what the status
   * region announces first) and, when web/refusal-explain.js is loaded,
   * ADDS the closed-table explanation beneath it.
   *
   * Nothing about the refusal changes: it is not softened, retried,
   * downgraded, or worked around, no override is ever offered, and a code
   * with no closed entry renders the server's message VERBATIM plus an
   * explicit "no closed explanation" line rather than a guess. A page
   * served without the module keeps the plain summary (fails closed to
   * less explanation, never to a wrong one). */
  const refusalExplain = () => (window.PolicyVaultRefusalExplain && typeof window.PolicyVaultRefusalExplain.renderRefusalHtml === "function" ? window.PolicyVaultRefusalExplain : null);
  function noteRefusal(prefix, e) {
    const code = (e && e.code) || "";
    const message = (e && e.message) || String(e || "refused");
    const summary = `${prefix}: ${code} ${message}`.replace(/\s+/g, " ").trim();
    note(summary, "bad");
    const mod = refusalExplain();
    const el = $("v4-notice");
    if (!mod || !el) return;
    try { el.innerHTML = mod.renderRefusalHtml({ summary, code, message }); }
    catch { /* the plain summary already stands; an explanation defect must never hide a refusal */ }
  }

  /* ---- OUTCOME RENDERING — PENDING IS NOT SUCCESS (TRACK 11) ----
   * A completed flow used to end at "agentSpend: SUBMITTED — txid abc…"
   * in an amber bar. The amber was correct and the state name was
   * truthful, but nothing SAID that a broadcast is not a confirmation, so
   * the most consequential distinction in the product was left for the
   * user to infer from a colour.
   *
   * noteOutcome() keeps the raw state and txid in the summary line
   * (unchanged, still the thing to quote in a support report) and adds
   * the state's meaning and next step. The success class is still granted
   * ONLY by the server's authoritative CHAIN_VERIFIED — and when the
   * explain module is present it decides that, so an UNRECOGNISED state
   * can never be presented as success. */
  function noteOutcome(prefix, state, txId, detail) {
    const mod = refusalExplain();
    const verified = mod && typeof mod.isVerifiedOutcome === "function" ? mod.isVerifiedOutcome(state) : state === "CHAIN_VERIFIED";
    const summary =
      `${prefix}: ${state}${txId ? ` — txid ${short(txId)}` : ""}${detail ? ` — ${detail}` : ""}` +
      (verified ? " (relayed + chain-verified)" : " — NOT YET CONFIRMED");
    note(summary, verified ? "good" : "warn");
    const el = $("v4-notice");
    if (!mod || !el || typeof mod.renderOutcomeHtml !== "function") return;
    try { el.innerHTML = mod.renderOutcomeHtml({ summary, state, txId, detail }); }
    catch { /* the plain summary already stands */ }
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
  /* v0.7 ON-CHAIN ORGANIZATIONAL ROOT (Wave 2, Track B-web). Requires BOTH
   * web/org-root-ui.js AND the v0.7 module closure inside window.PolicyVaultCore
   * (web/core-bundle.js) — a page served without either degrades to the
   * hosted-organization-only Organizations view (checked at every call site
   * below), never a broken or half-verified root surface. */
  const orgRootUI = () => (window.PolicyVaultOrgRootUI && window.PolicyVaultCore && window.PolicyVaultCore.ownerSetV7 ? window.PolicyVaultOrgRootUI.createModule({ api: { getJSON, postJSON, resolveXOnly }, core: window.PolicyVaultCore, setup: window.PolicyVaultSetupUi && window.PolicyVaultCore.durationDaa ? window.PolicyVaultSetupUi.createModule({ core: window.PolicyVaultCore }) : null }) : null);

  /* Owner ops are fuel-funded; auto-select the owner's largest ordinary
   * UTXO from the server. Module-scope (not just wireVault-local) so a
   * governance-ceremony RETRY reached from the persistent open-proposals
   * list (which has no live form params in hand — only the proposal's own
   * stored action/params, which never carry `fuel`; server/src/
   * governance.js stripExecutionOnlyParams excludes it by design) can
   * re-select fresh fuel exactly like the original action did, instead of
   * silently retrying with a missing/stale UTXO reference. */
  /* DISPLAY-ONLY KAS rendering through the canonical integer renderer
   * (core/model/amounts.js sompiToKas via the bundle); never floating point.
   * Fails closed to the raw sompi string when the core is unavailable. */
  const sompiToKasDisplay = (sompi) => {
    const core = typeof window !== "undefined" ? window.PolicyVaultCore : undefined;
    try {
      if (core && core.amounts && typeof core.amounts.sompiToKas === "function") return `${core.amounts.sompiToKas(BigInt(String(sompi)))} KAS`;
    } catch { /* fall through to the fail-closed rendering */ }
    return `${String(sompi)} sompi`;
  };
  const withFuel = async (params, minSompi = "200000000") => {
    try {
      // Immediate truthful feedback: the fuel read + build round-trips are
      // REQUIRED transaction inputs (never skipped), but the user should
      // see work started the instant they acted.
      note("Preparing transaction…", "warn");
      const { utxos } = await getJSON(`/wallet/fuel/${encodeURIComponent(state.address)}`);
      const u = (utxos || []).find((x) => BigInt(x.amount) > BigInt(minSompi));
      if (!u) { note(`No ordinary UTXO > ${sompiToKasDisplay(minSompi)} at ${short(state.address)} — fund the owner address first.`, "bad"); return null; }
      return { ...params, fuel: { outpoint: u.outpoint, amount: u.amount, scriptPublicKeyHex: u.scriptPublicKeyHex } };
    } catch (e) { note(`Could not fetch fuel: ${e.message}`, "bad"); return null; }
  };

  /* React to the ONE canonical wallet session. Account/network changes are
   * SECURITY EVENTS: re-derive the active identity, discard any in-progress
   * signing modal, and re-render (which re-runs role derivation + disables
   * actions when the wallet is not on the server's configured network). */
  async function updateWallet(snap) {
    const changed = snap.address !== state.address || snap.network !== state.network || snap.ready !== state.ready;
    // Hosted-session transitions (sign-in, sign-out, expiry, wallet/network
    // rebind) are identity events exactly like a wallet switch: retained
    // view data and shared in-flight reads are discarded, and the view
    // re-renders (which, signed in, starts fresh authoritative fetches —
    // the "prefetch after authentication" moment).
    const authChanged = (snap.auth ?? null) !== state.auth;
    // The NODE-reported network identity (GET /network/status, the same
    // value the signing gate compares against and the same value the top
    // banner derives from). Used ONLY to tell the user WHY signing is
    // disabled — never as a gate of its own. A change of it changes what
    // the not-ready explanation says, so it counts as a rendered change.
    const nodeNetChanged = (snap.serverNetwork ?? null) !== state.nodeNetwork;
    const hadXOnly = !!state.xonly;
    state.address = snap.ready ? snap.address : (snap.address || null);
    state.network = snap.network;
    state.ready = snap.ready;
    state.provider = snap.provider;
    state.auth = snap.auth ?? null;
    state.xonly = snap.xonly || null;
    state.nodeNetwork = snap.serverNetwork ?? null;
    if (changed || authChanged) dropRetainedState();
    // If the session hasn't resolved x-only yet but is ready, resolve it once.
    if (snap.ready && snap.address && !state.xonly) {
      try { state.xonly = await resolveXOnly(snap.address); } catch { state.xonly = null; }
    }
    const box = $("v4-wallet");
    if (box) {
      if (!snap.connected) box.innerHTML = `No wallet connected. <b>Connect KasWare in the Wallet panel above to continue.</b>`;
      else if (!snap.ready && !state.nodeNetwork) box.innerHTML = notReadyNodeUnknownHtml();
      else if (!snap.ready) box.innerHTML = `Wallet is on <b>${esc(snap.network || "unknown")}</b> — PolicyVault is configured for <b>${esc(networkLabel())}</b>. Switch KasWare to ${esc(networkLabel())} to sign.`;
      else box.innerHTML = `Signing wallet <span class="mono">${esc(snap.address)}</span> · network <b>${esc(snap.network)}</b> · <span class="badge ver">${esc(snap.provider || "wallet")}</span> · <span class="hint" style="display:inline">role is derived per vault below</span>`;
    }
    if (changed) {
      const m = $("v4-modal");
      if (m && m.style.display === "flex") { m.style.display = "none"; note("Wallet changed — the in-progress action was discarded. Rebuild it under the current wallet.", "warn"); }
      // A built-but-unsigned transaction, a draft review, or a root setup
      // belongs to the previous identity/network: invalidate them (stale
      // review/signature rule) — a new build under the current wallet is
      // required. Drafts are re-created from defaults on the next render.
      if (state.setup && state.setup.built) note("Wallet or network changed — the transaction built for review was discarded. Review and build it again under the current wallet.", "warn");
      state.setup = null;
      state.rootSetup = null;
    }
    // Re-render ONLY when something rendered actually changed (wallet identity/
    // network/readiness, a newly resolved x-only role key, or first paint).
    // Re-rendering on every identical session snapshot both wiped in-progress
    // form input and — before the one-time delegated wiring below — accumulated
    // duplicate listeners (the H2 approver-row multiplication bug).
    const xonlyChanged = !!state.xonly !== hadXOnly;
    if (changed || authChanged || xonlyChanged || nodeNetChanged || !state.renderedOnce) render();
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
      // FULL addresses, never short(): this is the message a user compares
      // against their wallet, and two accounts can share a truncation.
      if (expectedSigner && s.address !== expectedSigner) throw Object.assign(new Error(`connected wallet ${s.address} is not the expected signer ${expectedSigner}`), { code: "SIGNER_MISMATCH" });
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
        throw Object.assign(new Error(`wallet account/network changed during signing — refusing to submit a signature from a different identity (expected ${expectedSigner || "the connected account"}, now ${after.address || "disconnected"})`), { code: "SIGNER_CHANGED" });
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
  /* Friendly labels for the SERVER's canonical review keys (presentation
   * only — the values are the server's, verbatim; an unknown key keeps its
   * raw name rather than being hidden or guessed). */
  const REVIEW_LABELS = Object.freeze({
    action: "Action", network: "Network", vaultId: "Vault id", depositKas: "Deposit (protected)", reserveKas: "Fee reserve",
    agentCount: "Agents", maxPerSpendKas: "Maximum per payment", budget: "Spending budget", approvalAboveKas: "Payments need extra approval above",
    approvalPolicy: "Payment approvers", covenantId: "Covenant id", paymentKas: "Payment", recipientAddress: "Recipient wallet", recipient: "Recipient key",
    feeKas: "Network fee", feeSompi: "Network fee (sompi)", fundingMode: "Fee paid from", protectedBeforeKas: "Deposit before", protectedAfterKas: "Deposit after",
    reserveBeforeKas: "Fee reserve before", reserveAfterKas: "Fee reserve after", reserveConsumedKas: "Taken from the fee reserve", externalFuelKas: "Paid from your wallet",
    recoveredKas: "Returned to the owner", terminal: "Result", approvalsRequired: "Approvals required", policyNonceBefore: "Policy version before", policyNonceAfter: "Policy version after",
    predecessorStateId: "State id before", successorStateId: "State id after", successorAgentRoot: "Agent registry after", predecessorOutpoint: "Vault output being spent", computeBudget: "Compute budget"
  });
  const REVIEW_TECHNICAL_KEYS = new Set(["vaultId", "covenantId", "recipient", "feeSompi", "policyNonceBefore", "policyNonceAfter", "predecessorStateId", "successorStateId", "successorAgentRoot", "predecessorOutpoint", "computeBudget"]);
  const reviewLabel = (k) => (Object.prototype.hasOwnProperty.call(REVIEW_LABELS, k) ? REVIEW_LABELS[k] : k);
  const reviewValue = (k, v) => {
    if (k === "fundingMode") return v === "RESERVE-FUNDED" ? "the vault's fee reserve" : v === "FUEL-FUNDED" ? "your wallet (fuel input)" : String(v);
    if (/Kas$/.test(k) && typeof v === "string" && v !== "" && !/KAS/.test(v)) return `${v} KAS`;
    return String(v);
  };
  function reviewModal(review, onConfirm, confirmLabel, headline, verification, opts) {
    const o = opts || {};
    const rowsOf = (obj, filter) => Object.entries(obj || {})
      .filter(([k, v]) => v !== null && typeof v !== "object" && (!filter || filter(k)))
      .map(([k, v]) => `<tr><td class="rk">${esc(reviewLabel(k))}</td><td class="rv">${esc(reviewValue(k, v))}</td></tr>`)
      .join("");
    const rows = rowsOf(review, (k) => !REVIEW_TECHNICAL_KEYS.has(k));
    const techRows = rowsOf(review, (k) => REVIEW_TECHNICAL_KEYS.has(k)) + (review && review.technical ? rowsOf(review.technical) : "");
    const tech = techRows
      ? `<details class="adv"><summary>Technical details (exact protocol values)</summary><table class="review" style="width:100%">${techRows}</table></details>`
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
      ? `<div class="modal-actions"><button id="v4-cancel">${esc(o.cancelLabel || "Cancel")}</button><span class="setup-nav-spacer"></span>` +
        `<button id="v4-confirm" class="primary">${esc(confirmLabel || "Approve in wallet")}</button></div>`
      : `<div class="modal-actions"><button id="v4-cancel" class="primary">${esc(blocked ? "Close — do not sign" : o.cancelLabel || confirmLabel || "Close")}</button></div>`;
    const m = $("v4-modal");
    m.innerHTML =
      `<div class="modal-card setup-card" role="dialog" aria-modal="true"><h3>${esc(blocked ? "DO NOT SIGN — verification refused" : headline || "Review — exactly what your wallet will sign")}</h3>` +
      (canConfirm ? `<div class="f-help">Approving opens your wallet. A wallet signature is not yet a result: PolicyVault then submits the transaction and reports its state until it is verified on the chain.</div>` : "") +
      `<table class="review" style="width:100%">${rows}</table>` + (o.extraHtml || "") + tech + verifyHtml + actions + `</div>`;
    m.style.display = "flex";
    $("v4-cancel").onclick = async () => {
      m.style.display = "none";
      if (typeof o.onCancel === "function") { try { await o.onCancel(); } catch { /* best-effort */ } return; }
      if (!canConfirm) render();
    };
    const confirmBtn = $("v4-confirm");
    if (confirmBtn) confirmBtn.onclick = async () => {
      confirmBtn.disabled = true; // duplicate submission guard
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
      // Truthful progress states (PENDING IS NOT SUCCESS): every state
      // below is intermediate; only the server's CHAIN_VERIFIED outcome —
      // the existing authoritative chain-proof path — renders as success.
      note("Waiting for KasWare — review and approve in the wallet popup…", "warn");
      const signed = await walletSign(request.transaction.unsignedSafeJson, request.transaction.signInputs, state.address, verification);
      note(`${action}: signed — submitting for preflight…`, "warn");
      const done = await postJSON(`/wallet/v4/requests/${request.requestId}/signature`, { signedSafeJson: signed });
      if (done.request.state !== "PREFLIGHT_VERIFIED") {
        noteOutcome(action, done.request.state, null, done.request.error);
        render();
        return;
      }
      note(`${action}: preflight OK — broadcasting to ${networkLabel()}…`, "warn");
      const sub = await postJSON(`/wallet/v4/requests/${request.requestId}/submit`, {});
      noteOutcome(action, sub.request.state, sub.txId, sub.request.error);
      render();
    } catch (e) {
      noteRefusal(`${action} failed`, e);
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
      note("Preparing transaction…", "warn");
      const { request } = await postJSON("/wallet/v4/requests", { vaultId, action, params, signerAddress: state.address, ...(extra || {}) });
      note("");
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
      noteRefusal(`${action} rejected`, e);
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
      note("Waiting for KasWare — review and approve in the wallet popup…", "warn");
      const signed = await walletSign(t.unsignedSafeJson, entries, state.address, verification);
      note("Approval signed — recording…", "warn");
      stage = "L:post-approvals-started";
      const r = await postJSON(`/wallet/v4/requests/${req.requestId}/approvals`, { approverAddress: state.address, signedSafeJson: signed });
      stage = "M:server-response-received";
      note(`Approval recorded: ${r.approvals.collected} of ${r.approvals.required}${r.approvals.complete ? " — threshold met; the agent can now sign." : "."}`, "good");
      render(); // N: authoritative progress refreshed from server state
    } catch (e) {
      noteRefusal(`Approval rejected${e.walletStage ? "" : ` [stage ${stage}]`}`, e);
    }
  }

  /* ===================== CREATE VAULT (guided setup) =====================
   * Owner UX directive 2026-09-05: a short guided sequence — Basics and
   * ownership → Agent and recipients → Spending rules → Funding and review —
   * built from the SHARED setup components (web/setup-ui.js) the
   * organizational-root setup and the owner action forms reuse. Every step
   * panel stays in the DOM (inactive ones hidden), so Back / Continue and the
   * review's Edit links never lose entered values. Every duration goes
   * through core.durationDaa (the ONE conversion path); every amount through
   * core.amounts; every address through the server's one address-identity
   * boundary. The review the wallet signs against is the SERVER's own
   * review of the frozen build plus this browser's independent
   * verification — this form only carries intent.
   * ====================================================================== */
  const setupUi = () => (window.PolicyVaultSetupUi && window.PolicyVaultCore && window.PolicyVaultCore.durationDaa && window.PolicyVaultCore.amounts
    ? window.PolicyVaultSetupUi.createModule({ core: window.PolicyVaultCore })
    : null);
  // v0.4/v0.4.1 frozen consensus model: exactly 10 approver slots. UI limit
  // only mirrors it — the server/SDK independently rejects >10.
  const MAX_APPROVER_ROWS = 10;
  const VAULT_STEPS = Object.freeze([
    { id: "basics", label: "Basics and ownership" },
    { id: "agent", label: "Agent and recipients" },
    { id: "rules", label: "Spending rules" },
    { id: "funding", label: "Funding and review" }
  ]);

  // Address-example placeholder for the CONFIGURED network (cosmetic only).
  const addrExample = () => (state.serverNetwork === "mainnet" ? "kaspa:..." : "kaspatest:...");
  const ferr = (key) => `<div class="ferr" data-err="${key}"></div>`;

  /* The in-progress vault setup: draft values, current step, errors, and
   * the last SERVER build (kept so a wallet rejection returns to a
   * recoverable state without rebuilding). Discarded on every identity
   * change (see updateWallet). */
  function freshVaultSetup() {
    const su = setupUi();
    return { step: 0, draft: su ? su.vaultDraftDefaults() : null, errors: new Map(), built: null, busy: false, unresolved: [], unresolvedError: null, unresolvedChecked: false };
  }

  /* UX-05 (Codex checkpoint 2): a vault creation whose submit outcome is
   * uncertain stays a DURABLE server request (SUBMITTING / SUBMITTED /
   * RECONCILIATION_REQUIRED). The create flow reads that state from the
   * server on every render — so it survives retries, reloads and repeated
   * clicks — and refuses to build a replacement until the request is
   * RECONCILED by chain proof (CHAIN_VERIFIED or NOT_BROADCAST). A status
   * read never resolves it; an unreadable listing blocks (fail closed). */
  async function refreshUnresolvedCreations() {
    const s = vaultSetup();
    if (!state.ready || !state.address) { s.unresolved = []; s.unresolvedError = null; s.unresolvedChecked = true; return s; }
    try {
      const { requests } = await getJSON(`/wallet/v4/requests?unresolved=1&_=${Date.now()}`);
      s.unresolved = (Array.isArray(requests) ? requests : []).filter((r) => r && r.action === "createVault");
      s.unresolvedError = null;
    } catch (err) {
      s.unresolved = [];
      s.unresolvedError = `${err.code || ""} ${err.message || err}`.trim();
    }
    s.unresolvedChecked = true;
    return s;
  }
  function creationBlocked(s) { return !s.unresolvedChecked || s.unresolvedError !== null || s.unresolved.length > 0; }
  function unresolvedCreationHtml(s) {
    const esc_ = (v) => esc(String(v ?? ""));
    if (s.unresolvedError !== null) {
      return `<div class="opbanner warn" data-unresolved-create="error"><b>Cannot confirm whether an earlier vault creation is still unresolved</b> (${esc_(s.unresolvedError)}). Building a new vault is disabled until PolicyVault can read your durable requests. <button type="button" data-unresolved-refresh="1">Try again</button></div>`;
    }
    if (!s.unresolved.length) return "";
    return s.unresolved.map((r) => `<div class="opbanner warn" data-unresolved-create="${esc_(r.requestId)}"><b>A vault creation is still unresolved</b> — request <span class="mono">${esc_(r.requestId)}</span>${r.label ? ` ("${esc_(r.label)}")` : ""} is <b>${esc_(r.state)}</b>${r.txId ? ` (transaction <span class="mono">${esc_(r.txId)}</span>)` : ""}. The transaction may or may not have been broadcast. PolicyVault will not build or fund another vault until this one is resolved by chain proof — a status read, a lost response or a missing confirmation never counts as resolved.<div class="actions"><button type="button" class="primary" data-reconcile-create="${esc_(r.requestId)}">Reconcile against the chain</button></div></div>`).join("");
  }
  async function reconcileCreation(requestId) {
    const s = vaultSetup();
    if (s.busy) return;
    s.busy = true;
    rerenderCreate();
    try {
      note("Checking the Kaspa DAG for this creation…", "warn");
      const res = await postJSON(`/wallet/v4/requests/${encodeURIComponent(requestId)}/reconcile`, {});
      if (res.outcome === "CHAIN_VERIFIED") {
        noteOutcome("Create vault (reconciled)", res.request.state, res.txId, res.detail);
        s.built = null; state.setup = null; state.view = "vaults"; state.statusFilter = "Active";
        render();
        return;
      }
      if (res.outcome === "NOT_BROADCAST") note(`Resolved: ${res.detail}. Nothing left your wallet; you may build a vault again.`, "good");
      else if (res.outcome === "SUPERSEDED") note(`Resolved: ${res.detail}. This creation can never be mined (its funding was spent by another transaction); you may build a vault again.`, "good");
      else if (res.outcome === "ADVANCED_UNRESOLVED") note(`Unresolved — the vault EXISTS on chain: ${res.detail}. Do not build another vault; this creation needs manual reconciliation.`, "bad");
      else note(`Still unresolved (${res.outcome}): ${res.detail}. Do not sign or build again yet.`, "warn");
    } catch (err) { noteRefusal("Reconciliation did not complete", err); }
    s.busy = false;
    await refreshUnresolvedCreations();
    rerenderCreate();
  }
  function vaultSetup() {
    if (!state.setup || state.setup.kind !== "vault") state.setup = { kind: "vault", ...freshVaultSetup() };
    return state.setup;
  }

  /* OWNER AUTHORITY, STATED WHERE IT IS DECIDED (TRACK 11, finding T1;
   * scoped 2026-09-05). This vault TYPE commits exactly ONE owner key. The
   * statement is about this vault type — PolicyVault's on-chain
   * organizational root (Organizations tab) is the separate, real way to
   * hold shared ownership, so the warning must not become a product-wide
   * claim that no shared ownership exists. */
  const ownerStatementHtml = () =>
    `<div class="opbanner warn" data-owner-authority="1">` +
    `<b>This wallet becomes the vault's only owner key.</b>` +
    `<div class="f-help">This vault type (protocol v0.4.1) has no second owner, no owner quorum, and no organizational owner: only this wallet can pause the vault, add or remove agents, set approvers, and close &amp; recover. ` +
    `Hosted organizations are labels for grouping vaults and grant nobody owner authority. Shared ownership by several people is a different feature — an on-chain organizational root (Organizations tab) — and creating or joining a hosted organization does not provide it. ` +
    `Approvers set later can approve or refuse an agent's payment — they cannot spend, and they cannot act as the owner. ` +
    `PolicyVault holds no master key and offers no custodial recovery, so if this key is lost the owner controls are lost with it. Back this wallet up before funding the vault.</div></div>`;

  function createView() {
    const su = setupUi();
    if (!su) {
      return `<div class="panel"><h3 style="margin-top:0">Create vault</h3><div class="empty">The setup components did not load in this build — reload the page. Nothing was created.</div></div>`;
    }
    const s = vaultSetup();
    const d = s.draft;
    const err = (k) => s.errors.get(k) || "";
    const rowErr = (k) => s.errors.get(k) || {};
    const F = su.renderField;
    const hidden = (i) => (i === s.step ? "" : " hidden");
    const blocked = creationBlocked(s);
    const panel = (i, inner) => `<section class="setup-step" data-setup-step="${VAULT_STEPS[i].id}"${hidden(i)}><h3>${su.esc(VAULT_STEPS[i].label)}</h3>${inner}${su.renderNav({ index: i, total: VAULT_STEPS.length, finalLabel: blocked ? "Resolve the earlier creation first" : "Build & review exact transaction", busy: s.busy || (blocked && i === VAULT_STEPS.length - 1) })}</section>`;

    const basics =
      F({ name: "label", label: "Vault name", control: su.textInput({ name: "label", value: d.label, placeholder: "Operations Treasury", maxlength: 120 }), help: "A name for this vault in PolicyVault. It is not written to the chain.", error: err("label"), wide: true }) +
      `<div class="f f-wide"><div class="f-label">Owner</div><div class="addr-display"><span class="mono" data-owner-address="1">${esc(state.address)}</span> <span class="badge ver">Connected wallet</span> <button type="button" class="quiet addr-copy" data-copy="${esc(state.address)}">Copy</button></div>` +
      ownerStatementHtml() + `</div>`;

    const agent =
      F({ name: "agent", label: "Agent wallet", control: su.textInput({ name: "agent", value: d.agent, placeholder: addrExample(), mono: true }), help: `The wallet — often an AI agent or an automated service — allowed to make payments from this vault within the rules on the next step. It cannot change the rules and cannot act as the owner. ${docsLink("agent-delegate")}`, error: err("agent"), wide: true }) +
      `<div class="f f-wide${err("recipients") ? " f-invalid" : ""}" data-field="recipients"><div class="f-label">Allowed recipients</div>` +
      su.renderAddressRows({ kind: "recipient", rows: d.recipients, errors: rowErr("recipientRows"), addLabel: "Add recipient", placeholder: addrExample() }) +
      `<div class="f-help">Wallets this agent is allowed to pay. Enforced by the covenant on Kaspa, not only by this server: a payment to any other wallet is rejected even if the agent signs it directly. ${docsLink("destination-allowlist")}</div>` +
      `<div class="ferr" data-err="recipients"${err("recipients") ? ' style="display:block"' : ""}>${su.esc(err("recipients"))}</div></div>`;

    const approverCount = (d.approvers || []).filter((r) => r.address && r.address.trim()).length;
    const rules =
      `<div class="f-grid">` +
      F({ name: "maxPerSpend", label: "Maximum per payment", control: su.kasInput({ name: "maxPerSpend", value: d.maxPerSpend, placeholder: "2" }), help: `The most the agent may send in one payment. Enforced by the covenant on every payment, whoever signs it. ${docsLink("per-transaction-limit")}`, error: err("maxPerSpend") }) +
      F({ name: "budget", label: "Spending budget", control: su.kasInput({ name: "budget", value: d.budget, placeholder: "10" }), help: `The most the agent may send in total during one budget period. Must be at least the maximum per payment. ${docsLink("periodic-budget")}`, error: err("budget") }) +
      `</div>` +
      F({ name: "period", label: "Budget period", control: su.renderDurationControl({ name: "period", setting: su.BUDGET_SETTING, selection: d.period }), help: `${su.COPY.BUDGET_WINDOW} ${su.COPY.UNITS}`, error: err("period"), wide: true }) +
      F({ name: "approvalThreshold", label: "Payments that need extra approval", control: su.kasInput({ name: "approvalThreshold", value: d.approvalThreshold, placeholder: "1" }), help: `Payments <b>above</b> this amount need the approvers below to sign first; payments at or below it the agent signs alone. Enter 0 to require approval for every payment. ${docsLink("approval-threshold")}`, error: err("approvalThreshold") }) +
      `<div class="f f-wide${err("approvers") ? " f-invalid" : ""}" data-field="approvers"><div class="f-label">Payment approvers <span class="f-opt">(optional)</span></div>` +
      su.renderAddressRows({ kind: "approver", rows: d.approvers, errors: rowErr("approverRows"), addLabel: "Add approver", placeholder: addrExample(), min: 0, max: MAX_APPROVER_ROWS }) +
      `<div class="f-help">Wallets that can approve or refuse a payment above the threshold. They cannot spend, and they cannot act as the owner. An approver cannot spend vault funds or act as the owner. Leave empty for an agent-only vault. At most 10, each a distinct wallet. ${docsLink("external-approver")}</div>` +
      `<div class="ferr" data-err="approvers"${err("approvers") ? ' style="display:block"' : ""}>${su.esc(err("approvers"))}</div></div>` +
      F({ name: "approvalM", label: "Approvals needed", control: su.renderApprovalSelect({ name: "approvalM", count: approverCount, value: d.approvalM, noun: "approvers", max: MAX_APPROVER_ROWS }), help: approverCount ? `How many of the ${approverCount} approvers must sign a payment above the threshold. Example: 2 of 3 — any two of them. If you remove an approver later, this number is never lowered for you.` : "Add approvers above to choose how many must sign.", error: err("approvalM") }) +
      su.renderLiveSummary(su.vaultRulesSummary(d), "v4-create-summary");

    const funding =
      `<div class="f-grid">` +
      F({ name: "deposit", label: "Deposit", control: su.kasInput({ name: "deposit", value: d.deposit, placeholder: "100" }), help: "The KAS locked in the vault for the agent to spend under the rules. Only the owner can take it back (Close & recover).", error: err("deposit") }) +
      F({ name: "reserve", label: "Fee reserve", control: su.kasInput({ name: "reserve", value: d.reserve, placeholder: "5" }), help: `Pays the network fee of each agent payment so the deposit is never reduced by fees. When it runs out, agent payments made through PolicyVault stop until the owner tops it up. ${docsLink("fee-reserve")}`, error: err("reserve") }) +
      `</div>` +
      `<details class="adv"><summary>Advanced</summary>` +
      F({ name: "maxFee", label: "Maximum network fee per payment", control: su.kasInput({ name: "maxFee", value: d.maxFee, placeholder: "0.10" }), help: "Caps the fee a single agent payment may take from the reserve. Optional — the default (0.10 KAS) is comfortably above current v0.4.1 payment fees.", error: err("maxFee"), optional: true }) +
      F({ name: "creationMaxFee", label: "Maximum network fee for creating the vault", control: su.kasInput({ name: "creationMaxFee", value: d.creationMaxFee, placeholder: "1" }), help: "A limit for the ONE creation transaction, separate from the agent's per-payment cap: PolicyVault refuses to ask your wallet to sign if the exact creation fee is above it. Default 1 KAS; the real fee is normally far below 0.01 KAS.", error: err("creationMaxFee") }) +
      `<div class="f-help">Budget periods and waiting times are counted in Kaspa DAA score; wall-clock durations shown anywhere in this app are approximate.</div>` +
      `</details>` +
      `<div id="v4-create-review">${renderVaultDraftReview(su, d)}</div>` +
      `<div class="f-help">The next screen shows the exact transaction PolicyVault built from these values, re-verified independently by this browser, before your wallet is asked to sign.</div>`;

    return (
      `<div class="panel setup"><h3 style="margin-top:0">Create vault</h3>` +
      unresolvedCreationHtml(s) +
      su.renderStepper({ steps: VAULT_STEPS, current: s.step }) +
      `<form class="setup-form" id="v4-create-form" autocomplete="off" novalidate>` +
      panel(0, basics) + panel(1, agent) + panel(2, rules) + panel(3, funding) +
      `</form>` +
      (s.built ? `<div class="opbanner warn" data-built-pending="1">An exact transaction was already built from these values and is waiting for your signature. <button type="button" class="primary" id="v4-create-reopen">Open the review again</button> <span class="f-help" style="display:inline">Editing any field discards it.</span></div>` : "") +
      `</div>`
    );
  }

  /* The draft review (step 4) with Edit links — the INTENT the server will
   * build from. The exact-transaction review follows on build. */
  function renderVaultDraftReview(su, d) {
    const rows = draftReviewRowsBestEffort(su, d);
    return (
      `<h4 class="review-title">Review before building</h4>` +
      su.renderReviewSection({ title: "Basics and ownership", editStep: 0, rows: rows.basics }) +
      su.renderReviewSection({ title: "Agent and recipients", editStep: 1, rows: rows.agent }) +
      su.renderReviewSection({ title: "Spending rules", editStep: 2, rows: rows.rules }) +
      su.renderReviewSection({ title: "Funding", editStep: 3, rows: rows.funding, note: "The network fee is exact only once the transaction is built; it is shown on the next screen with the total leaving your wallet." })
    );
  }
  /* Synchronous best-effort rows from the raw draft (no address resolution). */
  function draftReviewRowsBestEffort(su, d) {
    const v = (x) => (String(x ?? "").trim() || "—");
    let period = "—";
    try { const n = su.readDurationSelection(su.BUDGET_SETTING, d.period); period = su.html(`${esc(n.describe.text)} (approximate)<details class="adv f-tech"><summary>Technical detail</summary>exactly ${esc(n.daa)} DAA score</details>`); } catch (e) { period = "not set"; }
    const approvers = (d.approvers || []).map((r) => (r.address || "").trim()).filter(Boolean);
    const recipients = (d.recipients || []).map((r) => (r.address || "").trim()).filter(Boolean);
    const H = su.html;
    return {
      basics: [["Vault name", v(d.label)], ["Owner", H(`<span class="mono">${esc(state.address)}</span> — the only owner key of this vault`)]],
      agent: [["Agent wallet", H(`<span class="mono">${esc(v(d.agent))}</span>`)], ["Allowed recipients", recipients.length ? H(recipients.map((a) => `<span class="mono">${esc(a)}</span>`).join("<br/>")) : "—"]],
      rules: [
        ["Maximum per payment", `${v(d.maxPerSpend)} KAS`],
        ["Spending budget", `${v(d.budget)} KAS per budget period`],
        ["Budget period", period],
        ["Payments needing extra approval", `above ${v(d.approvalThreshold)} KAS`],
        ["Approvals", approvers.length ? H(`${esc(v(d.approvalM))} of ${approvers.length} approvers<br/>${approvers.map((a) => `<span class="mono">${esc(a)}</span>`).join("<br/>")}`) : "none — payments above the threshold are refused"]
      ],
      funding: [["Deposit (protected)", `${v(d.deposit)} KAS`], ["Fee reserve", `${v(d.reserve)} KAS`], ["Maximum network fee per payment", d.maxFee && String(d.maxFee).trim() ? `${v(d.maxFee)} KAS` : "0.10 KAS (default)"], ["Network fee limit for creating the vault", d.creationMaxFee && String(d.creationMaxFee).trim() ? `${v(d.creationMaxFee)} KAS` : "1 KAS (default)"]]
    };
  }

  /* Read every named control of the create form into the draft. Rows are
   * read in DOM order; a removed row is simply absent. */
  function readVaultDraft(f) {
    const s = vaultSetup();
    const d = s.draft;
    const val = (n) => f.querySelector(`[name="${n}"]`)?.value ?? d[n] ?? "";
    d.label = val("label");
    d.agent = val("agent");
    d.maxPerSpend = val("maxPerSpend");
    d.budget = val("budget");
    d.approvalThreshold = val("approvalThreshold");
    d.deposit = val("deposit");
    d.reserve = val("reserve");
    d.maxFee = val("maxFee");
    d.creationMaxFee = val("creationMaxFee");
    d.approvalM = val("approvalM");
    const periodSel = f.querySelector('[name="period"]');
    if (periodSel) d.period = { preset: periodSel.value, customValue: f.querySelector('[name="periodValue"]')?.value ?? "", customUnit: f.querySelector('[name="periodUnit"]')?.value ?? "day", existingDaa: d.period && d.period.existingDaa };
    const rowsOf = (kind) => [...f.querySelectorAll(`[data-rows="${kind}"] .addr-row`)].map((row) => ({ address: row.querySelector(`[name="${kind}"]`)?.value ?? "", label: row.querySelector(`[name="${kind}Label"]`)?.value ?? "" }));
    const rec = rowsOf("recipient");
    if (f.querySelector('[data-rows="recipient"]')) d.recipients = rec.length ? rec : [{ address: "" }];
    if (f.querySelector('[data-rows="approver"]')) d.approvers = rowsOf("approver");
    return d;
  }

  function rerenderCreate() {
    const root = $("v4-root");
    if (!root || state.view !== "create") return;
    root.innerHTML = createView();
    wireCreateForm();
  }

  /* ---- ONE-TIME delegated click wiring (the approver-row-multiplication
   * fix, kept). Attached to the persistent #v4-root EXACTLY ONCE at startup —
   * never inside render() — so re-renders can never accumulate duplicate
   * listeners. Row add/remove, Back/Continue, Edit links and Copy all route
   * through here; each one reads the current values into the draft FIRST so
   * nothing typed is lost. */
  async function handleCreateRowClick(e) {
    const t = e.target && e.target.closest ? e.target.closest("button") : null;
    if (!t || state.view !== "create") return;
    const f = $("v4-create-form");
    const s = vaultSetup();
    if (!f || !s.draft) return;
    if (t.hasAttribute("data-reconcile-create")) { await reconcileCreation(t.getAttribute("data-reconcile-create")); return; }
    if (t.hasAttribute("data-unresolved-refresh")) { await refreshUnresolvedCreations(); rerenderCreate(); return; }
    if (t.id === "v4-add-recipient") {
      readVaultDraft(f); s.draft.recipients.push({ address: "" }); s.errors.delete("recipients"); s.errors.delete("recipientRows"); rerenderCreate();
    } else if (t.id === "v4-add-approver") {
      readVaultDraft(f);
      if (s.draft.approvers.length < MAX_APPROVER_ROWS) s.draft.approvers.push({ address: "" });
      s.errors.delete("approvers"); s.errors.delete("approverRows"); rerenderCreate();
    } else if (t.classList.contains("rm-recipient")) {
      readVaultDraft(f);
      const i = Number(t.closest(".addr-row")?.getAttribute("data-row"));
      if (s.draft.recipients.length > 1) s.draft.recipients.splice(i, 1);
      s.errors.delete("recipients"); s.errors.delete("recipientRows"); rerenderCreate();
    } else if (t.classList.contains("rm-approver")) {
      readVaultDraft(f);
      const i = Number(t.closest(".addr-row")?.getAttribute("data-row"));
      s.draft.approvers.splice(i, 1);
      // The approval count is NEVER lowered for the user: if it no longer
      // fits, the select shows it as impossible and asks for a new choice.
      s.errors.delete("approvers"); s.errors.delete("approverRows"); rerenderCreate();
    } else if (t.hasAttribute("data-setup-back")) {
      readVaultDraft(f); s.step = Math.max(0, s.step - 1); rerenderCreate();
    } else if (t.hasAttribute("data-setup-next")) {
      readVaultDraft(f);
      await validateVaultStep(s, VAULT_STEPS[s.step].id);
      if (![...s.errors.keys()].length) s.step = Math.min(VAULT_STEPS.length - 1, s.step + 1);
      rerenderCreate();
    } else if (t.hasAttribute("data-edit-step")) {
      readVaultDraft(f); s.step = Number(t.getAttribute("data-edit-step")) || 0;
      // rc15 review F-02: editing after a build abandons that build — withdraw
      // the server-side request too (best-effort, exactly as Back to edit does)
      // so open unsigned requests never pile up toward the quota.
      const abandoned = s.built; s.built = null;
      if (abandoned && abandoned.request && abandoned.request.requestId) { try { await postJSON(`/wallet/v4/requests/${encodeURIComponent(abandoned.request.requestId)}/reject`, {}); } catch { /* best-effort withdrawal of an unsigned build */ } }
      rerenderCreate();
    } else if (t.id === "v4-create-reopen") {
      if (s.built) openVaultBuildReview(s.built);
    } else if (t.hasAttribute("data-copy")) {
      try { await window.navigator.clipboard.writeText(t.getAttribute("data-copy")); note("Address copied.", "good"); } catch { note("Could not access the clipboard — select the address text to copy it.", "warn"); }
    } else {
      return;
    }
    e.preventDefault();
  }

  /* Validate ONE step (field-local errors), through the server's address
   * boundary for addresses. Errors are kept on the setup state so a
   * re-render shows them beside their fields. */
  async function validateVaultStep(s, stepId) {
    const su = setupUi();
    if (!su) return;
    s.busy = true;
    try {
      const { errors } = await su.validateVaultDraft(s.draft, { resolve: resolveXOnly, step: stepId });
      s.errors = errors;
    } finally {
      s.busy = false;
    }
  }

  /* Live controls: the duration effect line, the approvals select, the
   * summary. Cheap and synchronous; never a network call. */
  function syncCreateControls(ev) {
    const f = $("v4-create-form");
    const su = setupUi();
    if (!f || !su) return;
    const s = vaultSetup();
    const d = readVaultDraft(f);
    /* The review block (with its Edit buttons) is REPLACED only when the
     * draft actually changed, and never on a blur-driven "change" event:
     * replacing it between mousedown and click would detach the very Edit
     * button being pressed and swallow the click (real-browser finding,
     * 2026-09-05 harness). */
    const snapshot = JSON.stringify(d);
    const draftChanged = snapshot !== s.lastSyncSnapshot;
    s.lastSyncSnapshot = snapshot;
    const isBlurChange = !!(ev && ev.type === "change" && ev.target && ev.target.tagName === "INPUT");
    // duration: show/hide the custom row + effect line
    const sel = f.querySelector('[name="period"]');
    const custom = f.querySelector('[data-duration-custom="period"]');
    if (sel && custom) custom.hidden = sel.value !== "custom";
    const eff = f.querySelector('[data-duration-effect="period"]');
    if (eff) eff.textContent = su.durationEffectText(su.BUDGET_SETTING, d.period);
    const exact = f.querySelector('[data-duration-exact="period"]');
    if (exact) exact.textContent = su.durationExactText(su.BUDGET_SETTING, d.period);
    // approvals select: recompute options from the CURRENT rows, preserving the chosen value
    const mSel = f.querySelector('[name="approvalM"]');
    if (mSel) {
      const count = (d.approvers || []).filter((r) => r.address && r.address.trim()).length;
      const current = mSel.value;
      const options = su.approvalOptions(count, "approvers", { max: MAX_APPROVER_ROWS });
      if (current && !options.some((o) => o.value === current)) options.unshift({ value: current, label: `${current} of ${count} approvers — impossible, choose again` });
      if (!options.length) options.push({ value: "", label: "add approvers first" });
      mSel.innerHTML = options.map((o) => `<option value="${esc(o.value)}"${o.value === current ? " selected" : ""}>${esc(o.label)}</option>`).join("");
      if (!current && options[0]) mSel.value = options[0].value;
      const box = f.querySelector('.ferr[data-err="approvalM"]');
      const t = su.thresholdCheck({ count, value: mSel.value, noun: "approvers", label: "Approvals needed", max: MAX_APPROVER_ROWS });
      if (box && count > 0 && !t.ok) { box.textContent = t.message; box.style.display = "block"; }
      else if (box && !s.errors.get("approvalM")) { box.textContent = ""; box.style.display = "none"; }
    }
    const summary = $("v4-create-summary");
    if (summary && draftChanged) summary.outerHTML = su.renderLiveSummary(su.vaultRulesSummary(d), "v4-create-summary");
    const review = $("v4-create-review");
    if (review && s.step === 3 && draftChanged && !isBlurChange) review.innerHTML = renderVaultDraftReview(su, d);
  }

  /* Field-local error display: sets/clears .ferr blocks + input highlighting. */
  function showFieldErrors(f, errors) {
    f.querySelectorAll(".ferr").forEach((el) => { el.textContent = ""; el.style.display = "none"; });
    f.querySelectorAll(".f-invalid").forEach((el) => el.classList.remove("f-invalid"));
    for (const [key, err] of errors) {
      if (typeof err !== "string" && !(err && err.message)) continue;
      const box = f.querySelector(`.ferr[data-err="${key}"]`);
      const message = typeof err === "string" ? err : err.message;
      if (box) { box.textContent = message; box.style.display = "block"; }
      const field = f.querySelector(`[data-field="${key}"]`);
      if (field) field.classList.add("f-invalid");
      for (const el of (err && err.inputs) || []) el.classList.add("invalid");
    }
  }

  /* Wire the freshly rendered create form (the form element is NEW on each
   * render, so these listeners die with it — click wiring lives in the
   * one-time delegated handler above instead). */
  function wireCreateForm() {
    const f = $("v4-create-form");
    if (!f) return;
    f.addEventListener("input", (ev) => syncCreateControls(ev));
    f.addEventListener("change", (ev) => syncCreateControls(ev));
    syncCreateControls();
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      await buildAndReviewVault(f);
    });
  }

  /* BUILD & REVIEW: validate everything, POST the build, verify the frozen
   * transaction in this browser, and show the exact review. The draft is
   * never discarded on a refusal; the first step with a problem is shown. */
  async function buildAndReviewVault(f) {
    const su = setupUi();
    const s = vaultSetup();
    if (!su || s.busy) return;
    s.busy = true;
    const submitBtn = f.querySelector("[data-setup-build]");
    if (submitBtn) submitBtn.disabled = true;
    try {
      readVaultDraft(f);
      await refreshUnresolvedCreations();
      if (creationBlocked(s)) { note("An earlier vault creation is still unresolved — reconcile it against the chain before building another vault.", "bad"); rerenderCreate(); return; }
      note("Checking the form…", "warn");
      const vaultId = randomHex32();
      const { ok, errors, body, context } = await su.validateVaultDraft(s.draft, { resolve: resolveXOnly, signerAddress: state.address, vaultId });
      s.errors = errors;
      if (!ok) {
        const order = ["label", "agent", "recipients", "maxPerSpend", "budget", "period", "approvalThreshold", "approvers", "approvalM", "deposit", "reserve", "maxFee", "creationMaxFee"];
        const stepOf = { label: 0, agent: 1, recipients: 1, maxPerSpend: 2, budget: 2, period: 2, approvalThreshold: 2, approvers: 2, approvalM: 2, deposit: 3, reserve: 3, maxFee: 3, creationMaxFee: 3 };
        const first = order.find((k) => errors.has(k));
        if (first !== undefined) s.step = stepOf[first];
        s.busy = false;
        rerenderCreate();
        note("Fix the highlighted fields, then continue.", "bad");
        return;
      }
      let built;
      try {
        note("Building the exact transaction…", "warn");
        built = await postJSON("/wallet/v4/create", body);
      } catch (err) {
        s.busy = false;
        noteRefusal("Create refused", err);
        if (err && err.code === "CREATION_UNRESOLVED") { await refreshUnresolvedCreations(); rerenderCreate(); }
        return; // the draft stays exactly as entered
      }
      const request = built.request;
      // BROWSER-LOCAL GENESIS VERIFICATION against the client's own form
      // context (client-generated vaultId, typed deposit/reserve, resolved
      // approver identities, the connected owner identity).
      const verification = verifyForSigning({ request, createContext: context, role: "owner" });
      s.built = { request, verification, context };
      s.busy = false;
      note("");
      rerenderCreate();
      openVaultBuildReview(s.built);
    } finally {
      s.busy = false;
      if (submitBtn) submitBtn.disabled = false;
    }
  }

  /* The exact-transaction review: SERVER review of the frozen build (friendly
   * labels), the funding breakdown recomputed from the frozen bytes, this
   * browser's verification, then Sign. Cancel returns to the review step
   * with the draft intact; the abandoned build is withdrawn best-effort so
   * it never counts against the open-request quota. */
  function openVaultBuildReview(built) {
    const { request, verification } = built;
    const su = setupUi();
    const funding = su ? fundingBreakdownHtml(su, request, built.context) : "";
    reviewModal(request.review, () => signAndSubmitVaultGenesis(built), "Approve in wallet", "Review — exactly what your wallet will sign", verification, {
      extraHtml: funding,
      cancelLabel: "Back to edit",
      onCancel: async () => {
        const s = vaultSetup();
        s.built = null;
        try { await postJSON(`/wallet/v4/requests/${encodeURIComponent(request.requestId)}/reject`, {}); } catch { /* best-effort withdrawal of an unsigned build */ }
        rerenderCreate();
      }
    });
  }

  /* Deposit + fee reserve + the EXACT network fee (Σ inputs − Σ outputs of
   * the frozen unsigned transaction, decoded by the same verifier the
   * signing gate uses) = total leaving the funding wallet; change returns.
   * Derived from the existing funding model: the covenant output carries
   * deposit + reserve in ONE UTXO; the reserve is part of that output, not
   * an extra debit. */
  function fundingBreakdownHtml(su, request, context) {
    const r = request.review || {};
    const limitSompi = context && context.maxFeeSompi ? String(context.maxFeeSompi) : null;
    const depositKas = r.depositKas ?? "—";
    const reserveKas = r.reserveKas ?? "—";
    let feeKas = null;
    try {
      const gate = verifyGate();
      const dec = gate && typeof gate.decodeUnsignedSafeTransaction === "function" ? gate.decodeUnsignedSafeTransaction(request.transaction.unsignedSafeJson) : null;
      if (dec && dec.ok) {
        const tx = dec.transaction;
        const inSum = tx.inputs.reduce((a, i) => a + BigInt(i.utxo.amount), 0n);
        const outSum = tx.outputs.reduce((a, o) => a + BigInt(o.value), 0n);
        feeKas = window.PolicyVaultCore.amounts.sompiToKas(inSum - outSum);
      }
    } catch { feeKas = null; }
    const dep = su.kasToSompi(depositKas), res = su.kasToSompi(reserveKas);
    const total = dep !== null && res !== null && feeKas !== null ? su.sompiToKas(BigInt(dep) + BigInt(res) + BigInt(su.kasToSompi(feeKas))) : null;
    return su.renderFundingBreakdown({
      title: "What leaves your wallet",
      rows: [
        { label: "Deposit (protected, spendable by the agent under the rules)", kas: depositKas },
        { label: "Fee reserve (pays agent payment fees)", kas: reserveKas, note: "held inside the vault output with the deposit" },
        { label: "Network fee for creating the vault", kas: feeKas === null ? "unknown — verification did not decode the transaction" : feeKas, note: limitSompi ? `exact, from the frozen transaction; your limit for this transaction is ${su.sompiToKas(BigInt(limitSompi))} KAS (the browser refuses to sign above it)` : "exact, from the frozen transaction" }
      ],
      total: total !== null ? { label: "Total leaving your wallet", kas: total } : null,
      note: "Any remaining value of the funding input returns to your wallet as change. The deposit stays spendable only under the rules above; when the fee reserve is used up, agent payments through PolicyVault stop until you top it up."
    });
  }

  /* Sign → genesis-submit. A signature is not success; only the server's
   * CHAIN_VERIFIED renders as such. Wallet rejection or disconnect returns
   * to the review step with the built request kept (reopen without
   * rebuilding). An uncertain submission outcome offers a status check of
   * the EXISTING request before any new transaction. */
  async function signAndSubmitVaultGenesis(built) {
    const s = vaultSetup();
    if (s.busy) return;
    s.busy = true;
    const { request, verification } = built;
    let signed;
    try {
      // UX-05 (Codex checkpoint 3): the unresolved-creation invariant holds at
      // SIGNING too — a request built earlier (another tab, a reload) never
      // reaches the wallet while ANOTHER creation of this wallet is unresolved.
      await refreshUnresolvedCreations();
      const others = s.unresolved.filter((r) => r.requestId !== request.requestId);
      if (s.unresolvedError !== null || others.length) {
        s.busy = false;
        note(s.unresolvedError !== null ? "Cannot confirm whether an earlier vault creation is unresolved — not signing." : `Another vault creation (${others[0].requestId}, ${others[0].state}) is still unresolved — reconcile it before signing this one.`, "bad");
        rerenderCreate();
        return;
      }
      note("Waiting for your wallet — review and approve in the wallet popup…", "warn");
      signed = await walletSign(request.transaction.unsignedSafeJson, request.transaction.signInputs, state.address, verification);
    } catch (err) {
      s.busy = false;
      noteRefusal("Signing did not complete — nothing was sent", err);
      rerenderCreate();
      return;
    }
    try {
      note(`Approved in your wallet — submitting to ${networkLabel()}… (a signature is not yet a result)`, "warn");
      const done = await postJSON(`/wallet/v4/requests/${request.requestId}/genesis-submit`, { signedSafeJson: signed });
      const ok2 = done.request.state === "CHAIN_VERIFIED";
      noteOutcome("Create vault", done.request.state, done.txId, done.request.error);
      s.built = null;
      if (ok2) { state.setup = null; state.view = "vaults"; state.statusFilter = "Active"; }
      s.busy = false;
      render();
    } catch (err) {
      s.busy = false;
      // The outcome is UNCERTAIN (the request may or may not have been
      // broadcast). The durable request stays on the server in an unresolved
      // state; the create flow now blocks any replacement build until it is
      // reconciled by chain proof (UX-05). Nothing here may be signed again.
      noteRefusal("Submission outcome uncertain — do not sign again", err);
      await refreshUnresolvedCreations();
      if (!s.unresolved.some((r) => r.requestId === request.requestId) && s.unresolvedError === null) {
        // the server already knows a terminal outcome for it — show it
        try { const { request: fresh } = await getJSON(`/wallet/v4/requests/${encodeURIComponent(request.requestId)}?_=${Date.now()}`); noteOutcome("Create vault (durable state)", fresh.state, fresh.txId, fresh.error); if (fresh.state === "CHAIN_VERIFIED") { s.built = null; state.setup = null; state.view = "vaults"; render(); return; } } catch (e2) { noteRefusal("Status read failed", e2); }
      }
      rerenderCreate();
    }
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

  /* "per about 1 day" from the agent's exact periodLengthDaa through the ONE
   * conversion path; empty when the presentation lacks it or the core is
   * unavailable (never a guess). */
  function agentPeriodText(agent) {
    const core = typeof window !== "undefined" ? window.PolicyVaultCore : undefined;
    if (!core || !core.durationDaa || !agent || agent.periodLengthDaa === undefined) return "";
    try { return ` (per ${core.durationDaa.describeDaa(String(agent.periodLengthDaa), { largestUnit: "week" }).text})`; } catch { return ""; }
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
    /* THE ALLOWLIST IS THE POLICY — SHOW IT (TRACK 11, finding D1).
     * The recipient addresses are already in the vault presentation this
     * browser holds (server/src/api.js presents recipientAddresses beside
     * the x-only recipients, both derived from the root-verified durable
     * registry). Hiding them meant the one rule a delegate has to satisfy
     * on every spend was invisible, and the spend flow asked the user to
     * type an address that "must be in this agent's allowlist" without
     * ever showing that list. */
    const allow = Array.isArray(agent.recipientAddresses) ? agent.recipientAddresses : [];
    const allowBlock = allow.length
      ? `<details class="adv" data-allowlist="${esc(agent.agentPk)}"><summary>Allowed recipients (${allow.length}) — enforced by the covenant</summary>` +
        `<div class="hint">This agent can only pay these addresses. The rule is committed on-chain, so it holds even against a transaction submitted straight to a Kaspa node with this agent's key.</div>` +
        allow.map((a) => `<div class="mono id" style="margin-top:0.25rem">${esc(a)}</div>`).join("") +
        `</details>`
      : `<div class="hint" data-allowlist="${esc(agent.agentPk)}" data-allowlist-empty="1">Allowed recipients are not available in this vault view.</div>`;
    return (
      `<div class="field" style="margin-top:0.5rem">` +
      `<div class="k">agent ${isThisAgent ? "(you)" : ""}${terminal ? " (historical)" : ""}${suspMark}</div>` +
      // WHICH agent (TRACK 11, finding I1). The card showed an agent's
      // limits but never its identity, so an owner running several agents
      // could not tell them apart — and could not tell which one a
      // suspension, a removal, or a re-policy would hit. The address is
      // already in the presentation (server-derived from the registry's
      // x-only key); it is shown in full, never truncated.
      `<div class="mono id" data-agent-identity="${esc(agent.agentPk)}">${esc(agent.agentAddress || agent.agentPk)}</div>` +
      `<div class="v">max ${esc(agent.maxPerSpendKas)} KAS per payment · ${esc(agent.remainingBudgetKas)} of ${esc(agent.periodBudgetKas)} KAS left this period${agentPeriodText(agent)} · extra approval above ${esc(agent.approvalThresholdKas)} KAS ${spend}</div>` +
      allowBlock +
      (state.xonly === vault.owner && !terminal ? `<div class="actions"><button data-repolicy="${esc(agent.agentPk)}">Change rules</button><button data-rotate="${esc(agent.agentPk)}">Rotate key</button><button class="warn" data-remove="${esc(agent.agentPk)}">Remove agent</button>${suspBtn}</div>` : "") +
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
        `<button data-topup="${esc(vault.vaultId)}">Top up deposit</button><button data-topupreserve="${esc(vault.vaultId)}">Top up fee reserve</button>` +
        `<button data-setapprovers="${esc(vault.vaultId)}">Set payment approvers</button>` +
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
        `<div class="field"><div class="k">Deposit (protected)</div><div class="v">${esc(live.protectedValueKas || "—")} KAS</div></div>` +
        `<div class="field"><div class="k">Fee reserve</div><div class="v">${esc(live.feeReserveKas || "—")} KAS</div></div>` +
        `<div class="field"><div class="k">Agents</div><div class="v">${(vault.agents || []).length}</div></div>` +
        `<div class="field"><div class="k">Payment approvers</div><div class="v">${approverCount ? `${esc(live.approvalM || "0")} of ${approverCount} must approve` : "none"}</div></div>` +
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
      (Array.isArray(vault.approverAddresses) && vault.approverAddresses.filter(Boolean).length
        ? `<details class="adv" data-approvers="${esc(vault.vaultId)}"><summary>Payment approvers (${vault.approverAddresses.filter(Boolean).length}) — ${esc(live.approvalM || "0")} must approve a payment above an agent's threshold</summary>` +
          `<div class="hint">Approvers can approve or refuse such a payment; they cannot spend, and they cannot act as the owner.</div>` +
          vault.approverAddresses.filter(Boolean).map((a) => `<div class="mono id" style="margin-top:0.25rem">${esc(a)}</div>`).join("") + `</details>`
        : "") +
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
      root.innerHTML = !state.address
        ? `<div class="empty">Connect KasWare in the Wallet panel above to begin.</div>`
        : !state.nodeNetwork
          ? `<div class="empty">${notReadyNodeUnknownHtml()}</div>`
          : `<div class="empty">Wallet is not on ${esc(networkLabel())}. Signing is disabled until you switch KasWare to ${esc(networkLabel())}.</div>`;
      return;
    }
    if (state.view === "create") { await refreshUnresolvedCreations(); root.innerHTML = createView(); wireCreateForm(); return; }
    if (state.view === "orgs") { await renderOrgsView(root, stale); return; }
    if (state.view === "activity") { await renderActivityView(root, stale); return; }
    if (state.view === "support") { await renderSupportView(root, stale); return; }
    if (state.view === "advanced") {
      root.innerHTML = `<div class="panel"><h3 style="margin-top:0">Advanced</h3><div class="kv-line">Connected: <span class="mono">${esc(state.address)}</span> (x-only <span class="mono">${esc(short(state.xonly))}</span>) · network ${esc(state.network)}</div><div class="hint" style="margin-top:0.6rem">Legacy vault compatibility: existing v0.2 / v0.3 vaults remain supported for management, verification, history, and recovery in the collapsed section at the bottom of the page. New vaults always use the current protocol.</div></div>`;
      return;
    }
    await renderVaultsView(root, stale);
  }

  /* ---- retained-state view rendering (UX responsiveness pass) ----
   * Paint the last-good data for THIS identity epoch immediately (marked
   * "Refreshing…"), then fetch fresh authoritative data and repaint.
   * Guards, in order: the render-sequence guard (a newer render owns the
   * DOM) and the identity-epoch guard (data started under an older
   * wallet/network/session identity is DISCARDED — never painted, never
   * cached). A failed refresh never leaves retained content standing
   * silently: it drops the retained entry and renders the failure — or
   * the QUIET signed-out state when a hosted server refused an
   * unauthenticated read (an expected state, not an error). Display
   * orchestration only: no signing, verification, or authorization step
   * ever reads from this cache path. */
  const refreshingChip = `<div class="hint" data-v4-refreshing="1" style="margin-bottom:0.4rem">Refreshing…</div>`;
  async function renderRetained(root, stale, { view, what, signInWhat, fetchData, paint }) {
    // WALLET CONNECTED is not POLICYVAULT SESSION AUTHENTICATED. On a hosted
    // server with no authenticated session every privileged read is refused
    // (401), so the console does not issue them at all: it paints the quiet
    // sign-in state and waits for the auth transition (setAuthState →
    // canonical session snapshot → render). No retry, no polling loop;
    // wallet events while signed out re-render this quiet state without a
    // single request. Authentication semantics are untouched — a 401 stays
    // a genuine refusal whenever a read IS made (e.g. a session that expired
    // between the snapshot and the response), handled below exactly as
    // before. Self-hosted servers (auth DISABLED) keep their open reads.
    if (signedOutHosted()) {
      delete state.cache[view];
      root.innerHTML = `<div class="empty">${esc(signInWhat)}</div>`;
      return;
    }
    const epoch = dataEpoch();
    const cached = state.cache[view];
    if (cached && cached.epoch === epoch) paint(root, cached.data, true);
    else root.innerHTML = `<div class="empty">Loading ${esc(what)}…</div>`;
    let data;
    try {
      data = await fetchData();
    } catch (e) {
      if (stale() || dataEpoch() !== epoch) return;
      delete state.cache[view];
      const hosted = state.auth && state.auth !== "DISABLED";
      if (isAuthRefusal(e) && hosted) {
        // The server refused the read as unauthenticated. If this client
        // still believed its session AUTHENTICATED, the server invalidated
        // it out of band: ask the canonical session to re-read the server's
        // truth ONCE (it flips to EXPIRED/SIGNED_OUT and every consumer goes
        // quiet). Never retried here; the 401 stands as the refusal it is.
        if (!signedOutHosted()) {
          try { const s = window.PolicyVaultWalletSession; if (s && typeof s.revalidateAuth === "function") s.revalidateAuth(); } catch { /* best-effort */ }
        }
        root.innerHTML = `<div class="empty">${esc(signInWhat)}</div>`;
        return;
      }
      root.innerHTML = `<div class="empty">Could not load ${esc(what)}: ${esc(e.message)}</div>`;
      return;
    }
    if (stale() || dataEpoch() !== epoch) return;
    state.cache[view] = { epoch, data };
    paint(root, data, false);
  }

  async function renderVaultsView(root, stale) {
    await renderRetained(root, stale, {
      view: "vaults",
      what: "vaults",
      signInWhat: "Sign in to view your vaults.",
      fetchData: async () => {
        // INDEPENDENT reads run CONCURRENTLY (previously four serial
        // round-trips). Only the primary /vaults read is load-bearing —
        // the metadata/workflow reads keep their original best-effort
        // fallbacks and never block the vaults view. The per-vault
        // suspension reads follow as a second stage (they need the vault
        // list) exactly as before.
        const gov0 = govUI();
        const [vaultsRes, orgData, openReqsRes, govProposals] = await Promise.all([
          getJSON("/vaults"),
          getJSON("/organizations").catch(() => ({ organizations: [], assignments: {}, assignmentsVersion: null })),
          getJSON("/wallet/v4/requests?open=1").catch(() => ({ requests: [] })),
          gov0 ? gov0.fetchOpenProposals().catch(() => []) : Promise.resolve([])
        ]);
        const vaults = vaultsRes.vaults;
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
        return { vaults, orgData, openReqs: openReqsRes.requests || [], govProposals, suspByVault };
      },
      paint: paintVaultsView
    });
  }

  function paintVaultsView(root, data, refreshing) {
    const { vaults, orgData, openReqs, govProposals, suspByVault } = data;
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
    root.innerHTML = (refreshing ? refreshingChip : "") + bar + body;
    // wire filter bar
    root.querySelectorAll("[data-status]").forEach((b) => (b.onclick = () => { state.statusFilter = b.dataset.status; render(); }));
    const orgSel = $("v4-org");
    if (orgSel) orgSel.onchange = () => { state.org = orgSel.value; render(); };
    const ec = $("v4-empty-create");
    if (ec) ec.onclick = () => navigateTo("create");
    wireVault(root);
    wireOrgAssign(root);
  }

  /* ============ ORGANIZATIONS (off-chain application metadata) ============
   * Rename / Archive / Restore / Delete operate ONLY on local organization
   * metadata: they never change covenant authority, vault state, manifests,
   * or anything on-chain. Delete is blocked while vaults are assigned. */
  async function renderOrgsView(root, stale = () => false) {
    await renderRetained(root, stale, {
      view: "orgs",
      what: "organizations",
      signInWhat: "Sign in to use Organizations.",
      fetchData: async () => {
        // /organizations is load-bearing; /vaults (labels/assignment UI)
        // keeps its best-effort fallback. The two are independent reads
        // and run CONCURRENTLY (previously serial).
        const [data, vaultsRes] = await Promise.all([
          getJSON("/organizations"),
          getJSON("/vaults").catch(() => ({ vaults: [] }))
        ]);
        const vaults = vaultsRes.vaults || [];
        // Governance/risk controls per ACTIVE organization (item 3).
        // Best-effort and read-only display when the module or a fetch
        // fails — this view must never block on it (mirrors the
        // corrupt/error handling already used for organization records).
        const controlsUI = orgControlsUI();
        const controlsByOrg = new Map();
        if (controlsUI) {
          const act0 = (data.organizations || []).filter((o) => !o.error && o.status !== "ARCHIVED");
          await Promise.all(act0.map(async (o) => {
            try { controlsByOrg.set(o.orgId, await controlsUI.fetchControls(o.orgId)); }
            catch { controlsByOrg.set(o.orgId, null); }
          }));
        }
        // On-chain organizational roots (Wave 2, Track B-web): a SEPARATE
        // authority plane from the hosted-organization metadata above.
        // Best-effort — a page served without web/org-root-ui.js or an
        // older server with no /org-roots route degrades to the
        // hosted-organization-only view (never a broken half-render).
        const rootUI = orgRootUI();
        let orgRoots = [];
        let rootCapabilities = null;
        if (rootUI) {
          const [roots, capabilities] = await Promise.all([
            rootUI.fetchOrgRoots().catch(() => ({ orgRoots: [] })),
            getJSON("/capabilities").catch(() => null)
          ]);
          orgRoots = roots.orgRoots || [];
          rootCapabilities = capabilities;
        }
        return { data, vaults, controlsByOrg, orgRoots, rootCapabilities };
      },
      paint: paintOrgsView
    });
  }

  function paintOrgsView(root, fetched, refreshing) {
    const { data, vaults, controlsByOrg, orgRoots, rootCapabilities } = fetched;
    state.orgData = data;
    state.rootCapabilities = rootCapabilities;
    const labelOf = new Map((vaults || []).filter(Boolean).map((v) => [v.vaultId, v.label || short(v.vaultId)]));
    const assignments = data.assignments || {};
    const byOrg = {};
    for (const [vid, a] of Object.entries(assignments)) { (byOrg[a.orgId] = byOrg[a.orgId] || []).push(vid); }
    const orgs = (data.organizations || []).filter((o) => !o.error);
    const corrupt = (data.organizations || []).filter((o) => o.error);
    const act = orgs.filter((o) => o.status !== "ARCHIVED");
    const arch = orgs.filter((o) => o.status === "ARCHIVED");
    const unassigned = (vaults || []).filter((v) => v && v.vaultId && !assignments[v.vaultId]).map((v) => v.vaultId);
    const controlsUI = orgControlsUI();
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
    // v0.7 ON-CHAIN ORGANIZATIONAL ROOT (Wave 2, Track B-web, contract §0/§3):
    // rendered by web/org-root-ui.js — a SEPARATE authority plane from the
    // hosted-organization metadata below. Absent when the module or the v0.7
    // core bundle closure is not loaded (never a broken half-render).
    const rootUI = orgRootUI();
    const onChainRootSectionHtml = rootUI ? rootUI.renderOnChainRootSummaryHtml(orgRoots, rootCreationContext()) : "";

    root.innerHTML =
      (refreshing ? refreshingChip : "") +
      onChainRootSectionHtml +
      `<div class="panel"><h3 style="margin-top:0">Hosted organization (grouping &amp; roles — no on-chain authority)</h3>` +
      `<div class="hint">Organizations are off-chain application metadata: they group vaults for display and grant NO Kaspa covenant authority — not owner authority, not approver authority, and no recovery path. Each vault still has exactly one on-chain owner key, and covenant approvers are set on the vault itself. Archive hides an organization from normal selectors (recoverable); Delete is permanent and only possible once no vaults are assigned.</div>` +
      `<div class="org-assign" style="margin-top:0.7rem"><input id="v4-org-new-name" placeholder="New organization name" style="max-width:280px" /> <button id="v4-org-create-btn" class="primary">Create organization</button></div></div>` +
      (act.length ? act.map(orgRow).join("") : `<div class="empty">No active organizations.</div>`) +
      (arch.length ? `<h3 style="margin:1.2rem 0 0.6rem">Archived organizations</h3>` + arch.map(orgRow).join("") : "") +
      (corrupt.length ? `<div class="panel"><b>Metadata problems:</b> ${corrupt.map((c) => `${esc(c.orgId)} — ${esc(c.error)}`).join("; ")}</div>` : "");
    wireOrgs(root);
    wireOrgAssign(root);
    if (rootUI) wireOrgRoots(root, rootUI, orgRoots);
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

  /* ================================================================
   * v0.7 ON-CHAIN ORGANIZATIONAL ROOT — modal flows (Wave 2, Track B-web).
   * Every rendering call goes through window.PolicyVaultOrgRootUI
   * (web/org-root-ui.js); this block only wires the DOM and reuses the
   * SAME wallet session / walletSign-adapter pattern the rest of this file
   * already uses (session().adapter.signInputs). No amount here is ever
   * parsed with anything but the core bundle's canonical parsers.
   * ================================================================ */

  /* A caught error's display code, through org-root-ui's mapping of the
   * contract's closed v0.7 vocabulary — falls back to the raw code when
   * the module is unavailable, never invents one. */
  function noteRootRefusal(prefix, e, rootUI) {
    const code = rootUI && typeof rootUI.displayCodeFor === "function" ? rootUI.displayCodeFor(e) : (e && e.code) || "";
    noteRefusal(prefix, Object.assign(new Error((e && e.message) || String(e || "refused")), { code }));
  }

  /* The in-progress organizational-root setup (owner UX directive
   * 2026-09-05): Owners → Approval rules → Emergency access → Funding →
   * Review governance. Values live in a draft; every step panel stays in
   * the modal (inactive ones hidden), so Back / Continue / Edit never lose
   * entered values. Discarded on every identity change (updateWallet). */
  const ROOT_STEP_IDS = ["owners", "approvals", "emergency", "funding", "review"];
  const rootCreationContext = () => ({ networkId: state.nodeNetwork || state.serverNetwork, capabilities: state.rootCapabilities });

  /* A notice that belongs to the root setup wizard (progress, validation or a
   * BUILD refusal): cleared when the wizard is cancelled or its view is left,
   * and superseded by ANY newer notice (note() resets the flag first). */
  function noteRootWizard(msg, cls) { note(msg, cls); state.rootBuildRefusal = true; }

  function rootCreationAllowed(rootUI, setup) {
    const availability = rootUI && typeof rootUI.rootCreationAvailability === "function"
      ? rootUI.rootCreationAvailability(rootCreationContext())
      : { enabled: false, reason: "Organizational root creation availability could not be confirmed. Reopen Organizations to check again." };
    if (!availability.enabled) {
      noteRootWizard(availability.reason, "warn");
      if (setup) {
        setup.buildError = { message: availability.reason, availability: true };
        rerenderRootWizard();
      }
    }
    return availability.enabled;
  }

  function rootBuildErrorHtml(s) {
    if (!s.buildError) return "";
    const mod = refusalExplain();
    let html = esc(s.buildError.availability ? s.buildError.message : `${s.buildError.code} ${s.buildError.message}`);
    if (mod && !s.buildError.availability) {
      try { html = mod.renderRefusalHtml(s.buildError); } catch { /* retain the exact escaped refusal */ }
    }
    return `<div id="v4-orgroot-build-error" class="opbanner bad" role="alert" tabindex="-1">${html}</div>`;
  }

  function rootSetup(rootUI) {
    if (!state.rootSetup) {
      const su = setupUi();
      state.rootSetup = { step: 0, draft: su ? su.rootDraftDefaults(state.address) : null, errors: new Map(), built: null, buildError: null, busy: false };
    }
    if (rootUI) state.rootSetup.ui = rootUI;
    return state.rootSetup;
  }

  function wireOrgRoots(root, rootUI, orgRoots) {
    const btn = $("v4-orgroot-create-btn");
    if (btn) btn.onclick = () => openOrgRootWizard(rootUI);
    root.querySelectorAll("[data-viewroot]").forEach((b) => (b.onclick = () => openOrgRootDetail(rootUI, b.getAttribute("data-viewroot"))));
    void orgRoots;
  }

  /* Read every named control of the root setup form into the draft. */
  function readRootDraft(f) {
    const s = rootSetup();
    const d = s.draft;
    const val = (n, fallback) => { const el = f.querySelector(`[name="${n}"]`); return el ? el.value : fallback; };
    const checked = (n, fallback) => { const el = f.querySelector(`[name="${n}"]`); return el ? !!el.checked : fallback; };
    d.label = val("label", d.label);
    d.ownerM = val("ownerM", d.ownerM);
    d.emergencyK = val("emergencyK", d.emergencyK);
    d.recoveryEnabled = checked("recoveryEnabled", d.recoveryEnabled);
    d.recoveryM = val("recoveryM", d.recoveryM);
    d.successionEnabled = checked("successionEnabled", d.successionEnabled);
    d.successorAddress = val("successorAddress", d.successorAddress);
    d.rootValueKas = val("rootValueKas", d.rootValueKas);
    d.rootMaxFeePerTxKas = val("rootMaxFeePerTxKas", d.rootMaxFeePerTxKas);
    d.signerAddress = state.address || d.signerAddress;
    for (const k of ["recoveryDelay", "successionDelay"]) {
      const sel = f.querySelector(`[name="${k}"]`);
      if (sel) d[k] = { preset: sel.value, customValue: val(`${k}Value`, ""), customUnit: val(`${k}Unit`, "day") };
    }
    const rowsEl = f.querySelector('[data-rows="owner"]');
    if (rowsEl) {
      d.owners = [...rowsEl.querySelectorAll(".addr-row")].map((row) => {
        const keyEl = row.querySelector('[name="ownerKey"]');
        const keyMode = !!(keyEl && !keyEl.hidden);
        return {
          address: keyMode ? "" : (row.querySelector('[name="owner"]')?.value ?? ""),
          label: row.querySelector('[name="ownerLabel"]')?.value ?? "",
          publicKey: keyMode ? (keyEl.value ?? "") : "",
          keyMode
        };
      });
      if (!d.owners.length) d.owners = [{ address: "", label: "", publicKey: "" }];
    }
    return d;
  }

  function rerenderRootWizard() {
    const s = rootSetup();
    const m = $("v4-modal");
    if (!m || !s.ui || !s.draft) return;
    m.innerHTML = `<div class="modal-card setup-card" role="dialog" aria-modal="true" aria-labelledby="v4-orgroot-title">` +
      rootBuildErrorHtml(s) +
      s.ui.renderGenesisSetupHtml({ draft: s.draft, step: s.step, errors: s.errors, connectedAddress: state.address, busy: s.busy, network: networkLabel() }) +
      (s.built ? `<div class="opbanner warn" data-built-pending="1">A governance root transaction was already built from these values and is waiting for your signature. <button type="button" class="primary" id="v4-orgroot-reopen">Open the review again</button> <span class="f-help" style="display:inline">Editing any field discards it.</span></div>` : "") +
      `</div>`;
    m.style.display = "flex";
    const f = m.querySelector("[data-orgroot-wizard]");
    if (f) {
      f.addEventListener("input", (ev) => syncRootControls(ev));
      f.addEventListener("change", (ev) => syncRootControls(ev));
      f.addEventListener("submit", async (e) => { e.preventDefault(); await buildAndReviewRoot(); });
      syncRootControls();
      const first = $("v4-orgroot-build-error") || f.querySelector('section[data-setup-step]:not([hidden]) input, section[data-setup-step]:not([hidden]) select');
      if (first && typeof first.focus === "function") { try { first.focus(); } catch { /* focus is a nicety */ } }
    }
  }

  /* Live controls inside the root wizard: duration effect lines, threshold
   * selects recomputed from the CURRENT owner rows (never lowered), enable
   * toggles, the summary. Synchronous; never a network call. */
  function syncRootControls(ev) {
    const m = $("v4-modal");
    const f = m && m.querySelector ? m.querySelector("[data-orgroot-wizard]") : null;
    const s = rootSetup();
    const su = setupUi();
    if (!f || !su || !s.ui) return;
    const d = readRootDraft(f);
    const snapshot = JSON.stringify(d);
    const draftChanged = snapshot !== s.lastSyncSnapshot;
    s.lastSyncSnapshot = snapshot;
    const isBlurChange = !!(ev && ev.type === "change" && ev.target && ev.target.tagName === "INPUT");
    for (const [name, setting] of [["recoveryDelay", su.RECOVERY_SETTING], ["successionDelay", su.SUCCESSION_SETTING]]) {
      const sel = f.querySelector(`[name="${name}"]`);
      const custom = f.querySelector(`[data-duration-custom="${name}"]`);
      if (sel && custom) custom.hidden = sel.value !== "custom";
      const eff = f.querySelector(`[data-duration-effect="${name}"]`);
      if (eff) eff.textContent = su.durationEffectText(setting, d[name]);
      const exact = f.querySelector(`[data-duration-exact="${name}"]`);
      if (exact) exact.textContent = su.durationExactText(setting, d[name]);
    }
    const count = d.owners.filter((r) => (r.address && r.address.trim()) || (r.publicKey && r.publicKey.trim())).length;
    const m0 = /^[0-9]+$/.test(String(d.ownerM)) ? Number(d.ownerM) : 0;
    const refill = (name, max, label) => {
      const sel = f.querySelector(`[name="${name}"]`);
      if (!sel) return;
      const current = sel.value;
      const options = su.approvalOptions(count, "owners", { max });
      if (current && !options.some((o) => o.value === current)) options.unshift({ value: current, label: `${current} of ${count} owners — impossible, choose again` });
      if (!options.length) options.push({ value: "", label: "add owners first" });
      sel.innerHTML = options.map((o) => `<option value="${esc(o.value)}"${o.value === current ? " selected" : ""}>${esc(o.label)}</option>`).join("");
      if (!current && options[0]) sel.value = options[0].value;
      const box = f.querySelector(`.ferr[data-err="${name}"]`);
      const t = su.thresholdCheck({ count, value: sel.value, noun: "owners", label, max });
      if (box && !s.errors.get(name)) { box.textContent = count > 0 && !t.ok ? t.message : ""; box.style.display = count > 0 && !t.ok ? "block" : "none"; }
    };
    refill("ownerM", undefined, "Owners needed to approve changes");
    refill("emergencyK", m0 || undefined, "Owners needed for an emergency freeze");
    refill("recoveryM", m0 || undefined, "Owners needed to recover control");
    const recBox = f.querySelector("[data-recovery-fields]");
    if (recBox) recBox.hidden = !d.recoveryEnabled;
    const sucBox = f.querySelector("[data-succession-fields]");
    if (sucBox) sucBox.hidden = !d.successionEnabled;
    // The explanation under each toggle follows the toggle and the chosen
    // waiting period live (it is the explanation, not decoration).
    const recHelp = f.querySelector('[data-help="recovery"]');
    if (recHelp) recHelp.textContent = s.ui.recoveryHelpText(d);
    const sucHelp = f.querySelector('[data-help="succession"]');
    if (sucHelp) sucHelp.textContent = s.ui.successionHelpText(d);
    const summary = f.querySelector("[data-live-summary]");
    if (summary && draftChanged) summary.outerHTML = su.renderLiveSummary(su.rootRulesSummary(d), "v4-orgroot-summary");
    const review = f.querySelector("#v4-orgroot-review");
    if (review && s.step === 4 && draftChanged && !isBlurChange) review.innerHTML = s.ui.renderGenesisDraftReviewHtml({ draft: d, connectedAddress: state.address });
  }

  /* Delegated click wiring for the root wizard inside #v4-modal — attached
   * ONCE at startup (never per render), so re-renders cannot stack
   * listeners. Every navigation reads the current values into the draft
   * FIRST so nothing typed is lost. */
  async function handleModalSetupClick(e) {
    const t = e.target && e.target.closest ? e.target.closest("button") : null;
    if (!t) return;
    const m = $("v4-modal");
    const f = m && m.querySelector ? m.querySelector("[data-orgroot-wizard]") : null;
    const s = state.rootSetup;
    if (!f || !s || !s.draft) return;
    const su = setupUi();
    if (t.id === "v4-add-owner") {
      readRootDraft(f); if (s.draft.owners.length < 12) s.draft.owners.push({ address: "", label: "", publicKey: "" }); s.errors.delete("owners"); s.errors.delete("ownerRows"); rerenderRootWizard();
    } else if (t.classList.contains("rm-owner")) {
      readRootDraft(f);
      const i = Number(t.closest(".addr-row")?.getAttribute("data-row"));
      if (s.draft.owners.length > 1) s.draft.owners.splice(i, 1); else s.draft.owners = [{ address: "", label: "", publicKey: "" }];
      // Thresholds are NEVER lowered for the user — the selects flag an
      // impossible value and ask for an explicit choice.
      s.errors.delete("owners"); s.errors.delete("ownerRows"); rerenderRootWizard();
    } else if (t.hasAttribute("data-keytoggle")) {
      readRootDraft(f);
      const i = Number(t.getAttribute("data-keytoggle"));
      const row = s.draft.owners[i];
      // Advanced: a row is EITHER a wallet address OR a public key; toggling
      // clears the other form so a stale value can never be sent.
      if (row) s.draft.owners[i] = row.keyMode ? { ...row, keyMode: false, publicKey: "" } : { ...row, keyMode: true, address: "" };
      rerenderRootWizard();
    } else if (t.hasAttribute("data-use-connected")) {
      readRootDraft(f);
      const empty = s.draft.owners.findIndex((r) => !(r.address && r.address.trim()) && !(r.publicKey && r.publicKey.trim()));
      if (empty >= 0) s.draft.owners[empty] = { address: state.address, label: s.draft.owners[empty].label || "", publicKey: "" };
      else if (!s.draft.owners.some((r) => r.address === state.address) && s.draft.owners.length < 12) s.draft.owners.push({ address: state.address, label: "", publicKey: "" });
      else note("The connected wallet is already an owner.", "warn");
      rerenderRootWizard();
    } else if (t.hasAttribute("data-setup-back")) {
      readRootDraft(f); s.step = Math.max(0, s.step - 1); rerenderRootWizard();
    } else if (t.hasAttribute("data-setup-next")) {
      readRootDraft(f);
      if (su && s.ui) {
        s.busy = true;
        try { s.errors = (await s.ui.validateGenesisDraft(s.draft, { step: ROOT_STEP_IDS[s.step], connectedAddress: state.address })).errors; }
        finally { s.busy = false; }
      }
      if (![...s.errors.keys()].length) s.step = Math.min(ROOT_STEP_IDS.length - 1, s.step + 1);
      rerenderRootWizard();
    } else if (t.hasAttribute("data-edit-step")) {
      readRootDraft(f); s.step = Number(t.getAttribute("data-edit-step")) || 0;
      const abandoned = s.built; s.built = null; // rc15 review F-02: withdraw the abandoned build (best-effort)
      if (abandoned && abandoned.request) { try { await s.ui.rejectRequest(abandoned.request.rootCovenantId, abandoned.request.id, "withdrawn before signing"); } catch { /* best-effort */ } }
      rerenderRootWizard();
    } else if (t.hasAttribute("data-setup-cancel")) {
      readRootDraft(f);
      if (s.built) { try { await s.ui.rejectRequest(s.built.request.rootCovenantId, s.built.request.id, "withdrawn before signing"); } catch { /* best-effort */ } }
      state.rootSetup = null;
      m.style.display = "none";
      if (state.rootBuildRefusal) note(""); // the wizard's own progress / refusal notice leaves with it
      render();
    } else if (t.id === "v4-orgroot-reopen") {
      if (s.built) openRootBuildReview(s.built);
    } else if (t.hasAttribute("data-copy")) {
      try { await window.navigator.clipboard.writeText(t.getAttribute("data-copy")); note("Address copied.", "good"); } catch { note("Could not access the clipboard — select the address text to copy it.", "warn"); }
    } else {
      return;
    }
    e.preventDefault();
  }

  /* (b) ROOT SETUP — guided steps → exact governance review (rendered from
   * the SERVER's genesis summary cross-checked against the locally
   * normalized rules, plus the technical exact-policy panel) → funder signs
   * → PENDING (never success) → reconcile → live. */
  function openOrgRootWizard(rootUI) {
    if (!rootCreationAllowed(rootUI)) return;
    state.rootSetup = null;
    const s = rootSetup(rootUI);
    if (!s.draft) { note("The setup components did not load in this build — reload the page.", "bad"); return; }
    rerenderRootWizard();
  }

  async function buildAndReviewRoot() {
    const s = rootSetup();
    const m = $("v4-modal");
    const f = m && m.querySelector ? m.querySelector("[data-orgroot-wizard]") : null;
    if (!s.ui || !f || s.busy) return;
    if (!rootCreationAllowed(s.ui, s)) return;
    s.busy = true;
    s.buildError = null;
    try {
      readRootDraft(f);
      noteRootWizard("Checking the governance rules…", "warn");
      const v = await s.ui.validateGenesisDraft(s.draft, { connectedAddress: state.address });
      s.errors = v.errors;
      if (!v.ok) {
        const stepOf = { owners: 0, ownerM: 1, emergencyK: 2, recoveryM: 2, recoveryDelay: 2, successorAddress: 2, successionDelay: 2, rootValueKas: 3, rootMaxFeePerTxKas: 3, signerAddress: 3, label: 3 };
        const first = ["owners", "ownerM", "emergencyK", "recoveryM", "recoveryDelay", "successorAddress", "successionDelay", "rootValueKas", "rootMaxFeePerTxKas", "signerAddress", "label"].find((k) => v.errors.has(k));
        if (first !== undefined) s.step = stepOf[first];
        s.busy = false;
        rerenderRootWizard();
        noteRootWizard("Fix the highlighted fields, then continue.", "bad");
        return;
      }
      let created;
      try {
        noteRootWizard("Building the governance root transaction…", "warn");
        created = await s.ui.createGenesisRequest(v.form);
      } catch (err) {
        s.busy = false;
        // A cancelled setup's delayed BUILD refusal belongs to that setup,
        // not to the view or notice the owner has opened since then.
        if (state.rootSetup !== s || state.view !== "orgs") return;
        noteRootRefusal("Governance root refused", err, s.ui);
        state.rootBuildRefusal = true;
        s.buildError = { code: s.ui.displayCodeFor(err), message: (err && err.message) || String(err), summary: "Governance root refused" };
        rerenderRootWizard();
        return; // the draft stays exactly as entered
      }
      if (state.rootSetup !== s || state.view !== "orgs") {
        // The setup was cancelled (or its view left) while the build was in
        // flight: nobody is waiting for this review. Withdraw the late-built
        // request best-effort, exactly as Cancel does for a built request, and
        // never open a review over whatever the owner is doing now.
        try { await s.ui.rejectRequest(created.request.rootCovenantId, created.request.id, "withdrawn before signing"); } catch { /* best-effort */ }
        return;
      }
      const crossCheck = s.ui.genesisCrossCheck({ summary: created.request.manifest, norm: created.preview });
      s.built = { request: created.request, preview: created.preview, form: v.form, crossCheck };
      s.busy = false;
      note("");
      rerenderRootWizard();
      openRootBuildReview(s.built);
    } finally {
      s.busy = false;
    }
  }

  /* The exact governance review + sign. Cancel returns to the review step
   * with the draft intact (the abandoned build is withdrawn best-effort). */
  function openRootBuildReview(built) {
    const s = rootSetup();
    const m = $("v4-modal");
    if (!s.ui || !m) return;
    const { request, preview, crossCheck } = built;
    const canSign = crossCheck.ok;
    m.innerHTML =
      `<div class="modal-card setup-card" role="dialog" aria-modal="true" aria-labelledby="v4-orgroot-review-title">` +
      `<h3 id="v4-orgroot-review-title" style="margin-top:0">${canSign ? "Review governance — exactly what your wallet will sign" : "DO NOT SIGN — the built transaction does not match the reviewed rules"}</h3>` +
      s.ui.renderGenesisReviewHtml({ norm: preview, summary: request.manifest, crossCheck, connectedAddress: state.address }) +
      `<div class="modal-actions"><button type="button" id="v4-orgroot-review-back">Back to edit</button><span class="setup-nav-spacer"></span>` +
      (canSign ? `<button type="button" class="primary" id="v4-orgroot-confirm">Approve in wallet</button>` : `<button type="button" class="primary" id="v4-orgroot-review-back2">Close — do not sign</button>`) +
      `</div></div>`;
    m.style.display = "flex";
    const back = async () => {
      s.built = null;
      try { await s.ui.rejectRequest(request.rootCovenantId, request.id, "withdrawn before signing"); } catch { /* best-effort */ }
      s.step = 4;
      rerenderRootWizard();
    };
    $("v4-orgroot-review-back").onclick = back;
    const back2 = $("v4-orgroot-review-back2");
    if (back2) back2.onclick = back;
    const confirm = $("v4-orgroot-confirm");
    if (confirm) confirm.onclick = async () => {
      if (s.busy) return;
      s.busy = true;
      confirm.disabled = true;
      try {
        const sess = session();
        if (!sess.ready || !sess.adapter) throw Object.assign(new Error(`wallet is not connected on ${networkLabel()}`), { code: "WALLET_NOT_READY" });
        if (sess.address !== built.form.signerAddress) throw Object.assign(new Error(`connected wallet ${sess.address} is not the funding wallet ${built.form.signerAddress}`), { code: "SIGNER_MISMATCH" });
        note("Waiting for your wallet — review and approve the creation transaction…", "warn");
        let signed;
        try {
          signed = await s.ui.signGenesisRequest({ request, adapter: sess.adapter, network: sess.network, expectedSignerAddress: built.form.signerAddress, connectedXOnly: state.xonly, crossCheck: built.crossCheck, norm: built.preview });
        } catch (err) {
          s.busy = false;
          noteRootRefusal("Signing did not complete — nothing was sent", err, s.ui);
          rerenderRootWizard(); // recoverable: the built request is kept, reopen without rebuilding
          return;
        }
        note(`Governance root: ${signed.request.state} — submitting for broadcast…`, "warn");
        try {
          const sub = await s.ui.submitRequest(request.rootCovenantId, request.id, signed.request);
          noteOutcome("Organizational root creation", sub.request.state, sub.txId, sub.request.error);
          state.rootSetup = null;
          m.style.display = "none";
          render();
        } catch (err) {
          s.busy = false;
          noteRootRefusal("Submission outcome uncertain — do not sign again; open the root and use Verify state (reconcile) first", err, s.ui);
          m.style.display = "none";
          render();
        }
      } catch (err) {
        s.busy = false;
        noteRootRefusal("Organizational root creation failed", err, s.ui);
        confirm.disabled = false;
      }
    };
  }

  /* (c) ROOT DETAIL + (f) DANGEROUS ACTIONS confirmation before a request
   * for rotate/unfreeze/ownerRecover/succession is even created. The
   * current node DAA (best effort) lets the detail say how far a
   * recovery/succession wait has progressed — as an ESTIMATE; eligibility
   * is decided by the chain. */
  async function openOrgRootDetail(rootUI, rootId) {
    const m = $("v4-modal");
    m.innerHTML = `<div class="modal-card" style="max-width:640px;width:92%"><h3 style="margin-top:0">Loading organizational root…</h3></div>`;
    m.style.display = "flex";
    let orgRoot;
    let currentDaa = null;
    let rootedVaults = null; // R7-05: the presented summaries of the root's vaults (null = could not be loaded → no control offered)
    let pendingRequest = null; // F-6: the pending request record (reservation guidance names it and its authorized next step)
    try {
      ({ orgRoot } = await rootUI.fetchOrgRoot(rootId));
      const [daaRes, vaultsRes, pendingRes] = await Promise.all([
        getJSON("/network/status").then((r) => r.virtualDaaScore ?? null).catch(() => null),
        (orgRoot.vaults || []).length ? rootUI.fetchRootedVaults(rootId).then((r) => (Array.isArray(r.vaults) ? r.vaults : null)).catch(() => null) : Promise.resolve([]),
        orgRoot.pendingRequestId ? rootUI.fetchRequest(rootId, orgRoot.pendingRequestId).then((r) => r.request || null).catch(() => null) : Promise.resolve(null)
      ]);
      currentDaa = daaRes; rootedVaults = vaultsRes; pendingRequest = pendingRes;
    } catch (err) {
      note(`Could not load organizational root: ${err.code || ""} ${err.message}`, "bad");
      m.style.display = "none";
      return;
    }
    m.innerHTML =
      `<div class="modal-card setup-card" role="dialog" aria-modal="true">` +
      rootUI.renderRootDetailHtml(orgRoot, { viewerXOnly: state.xonly, viewerAddress: state.address, currentDaa, rootedVaults, pendingRequest }) +
      (orgRoot.pendingRequestId ? `<button data-vieworequest="${esc(orgRoot.pendingRequestId)}" class="primary">Open the pending request</button>` : "") +
      `<div class="modal-actions"><button id="v4-orgroot-detail-close">Close</button></div></div>`;
    $("v4-orgroot-detail-close").onclick = () => { m.style.display = "none"; render(); };
    m.querySelectorAll("[data-vieworequest]").forEach((b) => (b.onclick = () => openOrgRootRequestModal(rootUI, orgRoot, b.getAttribute("data-vieworequest"))));
    m.querySelectorAll("[data-rootaction]").forEach((b) => (b.onclick = () => openOrgRootActionFlow(rootUI, orgRoot, b.getAttribute("data-rootaction"))));
    /* R7-05: rooted-vault owner operations start HERE, from the vault's own panel, as ROOT REQUESTS. */
    m.querySelectorAll("[data-rootvaultop]").forEach((b) => (b.onclick = () => {
      const vault = Array.isArray(rootedVaults) ? rootedVaults.find((v) => v && v.vaultId === b.getAttribute("data-vault")) : null;
      if (!vault) { note("This vault's current state is not loaded — reload before starting an owner operation.", "bad"); return; }
      openRootedVaultOpFlow(rootUI, orgRoot, vault, b.getAttribute("data-rootvaultop"), { currentDaa });
    }));
    const rc = m.querySelector("[data-rootreconcile]");
    if (rc) rc.onclick = async () => {
      try {
        const res = await rootUI.reconcileRoot(rootId);
        const d = rootUI.describeReconcileOutcome(res); // UX-09: the NESTED reconciliation status decides the message — never a green label by default
        note(d.text, d.level);
      } catch (err) { noteRootRefusal("Verify state failed", err, rootUI); }
      openOrgRootDetail(rootUI, rootId);
    };
  }

  /* R7-05 (owner-approved browser initiation, launch scope 2026-09-08): a
   * rooted-vault OWNER operation — change agent rules / top up the fee
   * reserve / pause / unpause / emergency-pause / close & recover — started
   * from the vault's panel on the root detail. The browser collects the
   * operation's parameters (validated locally through the SAME core
   * normalizers the SDK builder runs), the server builds ONE root request
   * carrying ONE vaultOperations entry, and the request then follows the
   * ordinary M-of-N path (review → own-slot approvals → fee-payer finalize →
   * submit → verify). The draft stays exactly as entered after a refusal;
   * a double click cannot create two requests (busy latch + disabled
   * control); the dangerous close & recover needs its typed phrase. */
  function readVaultOpDraft(f, op, draft, rootUI) {
    const info = rootUI.vaultOpInfo(op);
    const val = (n, fallback) => { const el = f.querySelector(`[name="${n}"]`); return el ? el.value : fallback; };
    if (!info) return draft;
    if (info.form === "topUp") draft.amountKas = val("amount", draft.amountKas);
    else if (info.form === "agents") {
      draft.agents = [...f.querySelectorAll("[data-agent-row]")].map((row) => {
        const i = row.getAttribute("data-agent-row");
        const g = (k, fb) => { const el = row.querySelector(`[name="agent-${i}-${k}"]`); return el ? el.value : fb; };
        return { existing: g("existing", "0") === "1", agentKey: g("agentKey", ""), tokenMaxPerSpend: g("tokenMaxPerSpend", ""), tokenPeriodBudget: g("tokenPeriodBudget", ""), periodLengthDaa: g("periodLengthDaa", ""), periodStartDaa: g("periodStartDaa", "0"), tokenPeriodSpent: g("tokenPeriodSpent", "0"), agentMaxFeePerTxKas: g("agentMaxFeePerTxKas", ""), agentMaxCarryKas: g("agentMaxCarryKas", ""), recipients: g("recipients", "") };
      });
    } else draft.typed = val("typed", draft.typed);
    return draft;
  }
  async function openRootedVaultOpFlow(rootUI, orgRoot, vault, op, { currentDaa = null } = {}) {
    const m = $("v4-modal");
    const su = setupUi();
    const info = rootUI.vaultOpInfo(op);
    if (!info || !su || !m) { note(!info ? `Unsupported vault operation ${op} — failing closed.` : "The setup components did not load in this build — reload the page.", "bad"); return; }
    const avail = rootUI.vaultOpAvailability({ op, vault, orgRoot, viewerXOnly: state.xonly, networkId: orgRoot.networkId || null });
    if (!avail.enabled) { note(`${info.label} is not available: ${avail.reason}`, "bad"); return; }
    let draft;
    try { draft = rootUI.vaultOpDraftFrom({ op, vault, currentDaa }); } catch (err) { noteRootRefusal(`${info.label} refused`, err, rootUI); return; }
    let errors = new Map();
    let busy = false;
    const paint = () => {
      m.innerHTML = `<div class="modal-card setup-card" role="dialog" aria-modal="true" aria-labelledby="v4-vaultop-title">` + rootUI.renderVaultOpFormHtml({ op, vault, orgRoot, draft, errors, connectedAddress: state.address, currentDaa }) + `</div>`;
      m.style.display = "flex";
      const f = m.querySelector("[data-vaultop-form]");
      if (!f) return;
      const first = f.querySelector('input:not([type="hidden"]), textarea, select');
      if (first && typeof first.focus === "function") { try { first.focus(); } catch { /* nicety */ } }
      f.querySelectorAll("[data-vaultop-cancel]").forEach((b) => (b.onclick = () => { m.style.display = "none"; openOrgRootDetail(rootUI, orgRoot.rootCovenantId); }));
      const addBtn = f.querySelector("#v4-add-agent");
      if (addBtn) addBtn.onclick = () => { readVaultOpDraft(f, op, draft, rootUI); draft.agents.push(rootUI.vaultOpDraftFrom({ op, vault: { agents: [] }, currentDaa }).agents[0]); errors.delete("agentRows"); paint(); };
      f.querySelectorAll("[data-remove-agent]").forEach((b) => (b.onclick = () => { readVaultOpDraft(f, op, draft, rootUI); draft.agents.splice(Number(b.getAttribute("data-remove-agent")), 1); errors.delete("agentRows"); paint(); }));
      f.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (busy) return;
        busy = true;
        const submitBtn = f.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        try {
          readVaultOpDraft(f, op, draft, rootUI);
          const v = await rootUI.validateVaultOpDraft({ op, draft, vault, currentDaa });
          errors = v.errors;
          if (!v.ok) { busy = false; paint(); note("Fix the highlighted fields, then continue.", "bad"); return; }
          note(`Preparing ${info.label.toLowerCase()} — PolicyVault is building the exact transaction…`, "warn");
          let request;
          try {
            request = await rootUI.createRootRequest(orgRoot, { action: info.rootAction, params: {}, vaultOperations: [v.vaultOperation], signerAddress: state.address });
          } catch (err) {
            busy = false;
            noteRootRefusal(`${info.label} refused — nothing was created`, err, rootUI);
            paint(); // the draft stays exactly as entered
            return;
          }
          note(`${info.label}: request created — waiting for owner approvals; nothing has changed on-chain.`, "warn");
          openOrgRootRequestModal(rootUI, orgRoot, request.id, request);
        } catch (err) {
          busy = false;
          noteRootRefusal(`${info.label} failed`, err, rootUI);
          paint();
        }
      });
    };
    paint();
  }

  /* UX-10 (Codex checkpoint 2): sign + submit a succession request as the
   * designated successor. Used when the request is created and again from
   * the request detail to RESUME the same durable request after a wallet
   * rejection, a disconnect, a reload or a reopen. */
  async function signSuccessionRequest(rootUI, orgRoot, request, signerAddress) {
    const m = $("v4-modal");
    const s = session();
    try {
      if (!s.ready || !s.adapter) throw Object.assign(new Error(`wallet is not connected on ${networkLabel()}`), { code: "WALLET_NOT_READY" });
      const signed = await rootUI.signSingleSignerRequest({ request, adapter: s.adapter, network: s.network, expectedSignerAddress: signerAddress || state.address, connectedXOnly: state.xonly });
      note(`${rootUI.actionLabel("succession")}: ${signed.request.state} — submitting…`, "warn");
      const sub = await rootUI.submitRequest(orgRoot.rootCovenantId, request.id, signed.request);
      noteOutcome(rootUI.actionLabel("succession"), sub.request.state, sub.txId, sub.request.error);
      m.style.display = "none";
      render();
    } catch (err) {
      noteRootRefusal("Succession approval did not complete — the request is kept; reopen it to continue", err, rootUI);
      openOrgRootRequestModal(rootUI, orgRoot, request.id);
    }
  }

  /* (d) create a root action request. Change owners / recover control /
   * succession collect a new owner set first through the SAME owner rows
   * and "k of N owners" selects as the setup (never comma-delimited text).
   * (f) every dangerous action requires the exact typed confirmation
   * before anything is created. */
  async function openOrgRootActionFlow(rootUI, orgRoot, action) {
    const m = $("v4-modal");
    const NEEDS_NEW_SET = action === "rotate" || action === "ownerRecover" || action === "succession";

    async function proceed(params) {
      if (rootUI.isDangerousAction(action)) {
        const delayDaa = action === "ownerRecover"
          ? (orgRoot.template && orgRoot.template.recoveryDelayDaa)
          : action === "succession" ? (orgRoot.template && orgRoot.template.successionDelayDaa) : null;
        m.innerHTML =
          `<div class="modal-card setup-card" role="dialog" aria-modal="true">` +
          rootUI.renderDangerousConfirmHtml({ action, rootLabel: orgRoot.label || orgRoot.rootCovenantId, delayDaa, orgRoot }) +
          `<div class="f" style="margin-top:0.6rem"><label class="f-label" for="v4-orgroot-typed">Type the confirmation phrase</label><input id="v4-orgroot-typed" class="mono" placeholder="${esc(rootUI.dangerousConfirmPhrase(action))}" autocomplete="off" /></div>` +
          `<div class="modal-actions"><button id="v4-orgroot-danger-cancel">Cancel</button><span class="setup-nav-spacer"></span><button id="v4-orgroot-danger-confirm" class="warn">${esc(rootUI.actionLabel(action))}</button></div></div>`;
        m.style.display = "flex";
        $("v4-orgroot-danger-cancel").onclick = () => { m.style.display = "none"; openOrgRootDetail(rootUI, orgRoot.rootCovenantId); };
        $("v4-orgroot-danger-confirm").onclick = async () => {
          const typed = $("v4-orgroot-typed").value;
          if (!rootUI.typedConfirmationMatches(action, typed)) {
            note(`Type exactly "${rootUI.dangerousConfirmPhrase(action)}" to continue.`, "bad");
            return;
          }
          await createAndOpen(params);
        };
        return;
      }
      await createAndOpen(params);
    }

    async function createAndOpen(params) {
      try {
        note(`Preparing ${rootUI.actionLabel(action).toLowerCase()} request…`, "warn");
        const signerAddress = action === "succession" ? (params && params.successorAddress) || state.address : state.address;
        const request = await rootUI.createRootRequest(orgRoot, { action, params: (params && params.params) || {}, signerAddress });
        note(`${rootUI.actionLabel(action)}: request created — waiting for owner approvals; nothing has changed on-chain.`, "warn");
        if (action === "succession") {
          // single-signer path (the pinned successor key, not the owner blob).
          // UX-10: the DURABLE request is created first; a wallet rejection or
          // disconnect while signing keeps it, and the successor resumes it
          // from the request detail (no duplicate creation).
          await signSuccessionRequest(rootUI, orgRoot, request, signerAddress);
        } else {
          openOrgRootRequestModal(rootUI, orgRoot, request.id, request);
        }
      } catch (err) { noteRootRefusal(`${rootUI.actionLabel(action)} failed`, err, rootUI); }
    }

    if (!NEEDS_NEW_SET) { await proceed(null); return; }

    // New owner set — the same owner rows + "k of N owners" selects as setup.
    const su = setupUi();
    if (!su) { note("The setup components did not load in this build — reload the page.", "bad"); return; }
    const draft = rootUI.newOwnerSetDraftFrom(orgRoot, { action, connectedAddress: state.address });
    let errors = new Map();
    const paint = () => {
      m.innerHTML = `<div class="modal-card setup-card" role="dialog" aria-modal="true">` + rootUI.renderNewOwnerSetHtml({ action, orgRoot, draft, errors, connectedAddress: state.address }) + `</div>`;
      m.style.display = "flex";
      const f = m.querySelector("[data-orgroot-newset]");
      const read = () => {
        const rowsEl = f.querySelector('[data-rows="owner"]');
        if (rowsEl) draft.owners = [...rowsEl.querySelectorAll(".addr-row")].map((row) => ({ address: row.querySelector('[name="owner"]')?.value ?? "", label: row.querySelector('[name="ownerLabel"]')?.value ?? "", publicKey: row.querySelector('[name="ownerKey"]') && !row.querySelector('[name="ownerKey"]').hidden ? row.querySelector('[name="ownerKey"]').value : "" }));
        for (const k of ["ownerM", "emergencyK", "recoveryM", "successorAddress"]) { const el = f.querySelector(`[name="${k}"]`); if (el) draft[k] = el.value; }
        const rec = f.querySelector('[name="recoveryEnabled"]'); if (rec) draft.recoveryEnabled = !!rec.checked;
      };
      const sync = () => {
        read();
        const count = draft.owners.filter((r) => (r.address && r.address.trim()) || (r.publicKey && r.publicKey.trim())).length;
        const m0 = /^[0-9]+$/.test(String(draft.ownerM)) ? Number(draft.ownerM) : 0;
        for (const [name, max] of [["ownerM", undefined], ["emergencyK", m0 || undefined], ["recoveryM", m0 || undefined]]) {
          const sel = f.querySelector(`[name="${name}"]`);
          if (!sel) continue;
          const current = sel.value;
          const options = su.approvalOptions(count, "owners", { max });
          if (current && !options.some((o) => o.value === current)) options.unshift({ value: current, label: `${current} of ${count} owners — impossible, choose again` });
          if (!options.length) options.push({ value: "", label: "add owners first" });
          sel.innerHTML = options.map((o) => `<option value="${esc(o.value)}"${o.value === current ? " selected" : ""}>${esc(o.label)}</option>`).join("");
          if (!current && options[0]) sel.value = options[0].value;
        }
        const recBox = f.querySelector("[data-recovery-fields]"); if (recBox) recBox.hidden = !draft.recoveryEnabled;
        const recHelp = f.querySelector('[data-help="recovery"]'); if (recHelp) recHelp.textContent = rootUI.newOwnerSetRecoveryHelp(draft, orgRoot);
        const summary = f.querySelector("[data-live-summary]"); if (summary) summary.outerHTML = su.renderLiveSummary(rootUI.newOwnerSetSummary(draft, orgRoot), "v4-newset-summary");
      };
      f.addEventListener("input", sync);
      f.addEventListener("change", sync);
      sync();
      m.querySelectorAll("button").forEach((b) => {
        b.onclick = async (e) => {
          if (b.id === "v4-add-owner") { e.preventDefault(); read(); if (draft.owners.length < 12) draft.owners.push({ address: "", label: "", publicKey: "" }); errors.delete("owners"); errors.delete("ownerRows"); paint(); }
          else if (b.classList.contains("rm-owner")) { e.preventDefault(); read(); const i = Number(b.closest(".addr-row")?.getAttribute("data-row")); if (draft.owners.length > 1) draft.owners.splice(i, 1); errors.delete("owners"); errors.delete("ownerRows"); paint(); }
          else if (b.hasAttribute("data-keytoggle")) { e.preventDefault(); read(); const i = Number(b.getAttribute("data-keytoggle")); const row = draft.owners[i]; if (row) draft.owners[i] = b.textContent.trim() === "Use public key" ? { ...row, address: "", publicKey: "", keyMode: true } : { ...row, publicKey: "", keyMode: false }; paint(); }
          else if (b.hasAttribute("data-use-connected")) { e.preventDefault(); read(); const empty = draft.owners.findIndex((r) => !(r.address && r.address.trim()) && !(r.publicKey && r.publicKey.trim())); if (empty >= 0) draft.owners[empty] = { address: state.address, label: draft.owners[empty].label || "", publicKey: "" }; else if (draft.owners.length < 12) draft.owners.push({ address: state.address, label: "", publicKey: "" }); paint(); }
          else if (b.hasAttribute("data-setup-cancel")) { e.preventDefault(); m.style.display = "none"; openOrgRootDetail(rootUI, orgRoot.rootCovenantId); }
        };
      });
      f.addEventListener("submit", async (e) => {
        e.preventDefault();
        read();
        try {
          const v = await rootUI.validateNewOwnerSetDraft(draft, { action, orgRoot });
          errors = v.errors;
          if (!v.ok) { paint(); note("Fix the highlighted fields, then continue.", "bad"); return; }
          await proceed({ params: v.params, successorAddress: draft.successorAddress });
        } catch (err) {
          noteRootRefusal(`${rootUI.actionLabel(action)} refused`, err, rootUI);
        }
      });
    };
    paint();
  }

  /* (d) REQUEST review + M-of-N SLOT SIGNING. Own slot only, through the
   * signer adapter; other owners' envelopes are imported (paste / file).
   * Finalize offered only when present >= required; submit only after
   * SIGNED. */
  /* the successor a succession request installs as its sole owner (x-only), or null */
  /* rc18 review R3-03 / Codex UX-10: succession is authorized by the root's
   * PINNED successor key (the manifest's root template; the durable root
   * record as a cross-check), independent of the owner set it installs. */
  function successionSignerOf(request, orgRoot) {
    const fromManifest = request && request.manifest && request.manifest.root && request.manifest.root.template ? String(request.manifest.root.template.successorPk || "").toLowerCase() : "";
    const fromRoot = orgRoot && orgRoot.template ? String(orgRoot.template.successorPk || "").toLowerCase() : "";
    const pinned = fromManifest || fromRoot;
    if (!/^[0-9a-f]{64}$/.test(pinned) || pinned === "00".repeat(32)) return null;
    if (fromManifest && fromRoot && fromManifest !== fromRoot) return null; // the request and the root disagree — offer nothing
    return pinned;
  }
  async function openOrgRootRequestModal(rootUI, orgRoot, requestId, preloaded) {
    const m = $("v4-modal");
    async function repaint() {
      let request = preloaded;
      preloaded = null;
      if (!request) {
        try { ({ request } = await rootUI.fetchRequest(orgRoot.rootCovenantId, requestId)); }
        catch (err) { note(`Could not load request: ${err.code || ""} ${err.message}`, "bad"); m.style.display = "none"; return; }
      }
      let currentDaa = null;
      try { currentDaa = (await getJSON("/network/status")).virtualDaaScore ?? null; } catch { currentDaa = null; }
      const s = session();
      const mySlot = (request.slots || []).find((sl) => sl.publicKey && state.xonly && sl.publicKey.toLowerCase() === state.xonly.toLowerCase());
      m.innerHTML =
        `<div class="modal-card setup-card" role="dialog" aria-modal="true">` +
        rootUI.renderRequestDetailHtml(request, { orgRoot, viewerXOnly: state.xonly, viewerAddress: state.address, currentDaa }) +
        (mySlot && mySlot.status === "PENDING" && request.state === "AUTHORIZED" // rc16 review N-02: approvals only while AUTHORIZED
          ? `<div class="actions"><button id="v4-orgroot-signmyslot" class="primary" data-slot="${esc(mySlot.slot)}">Approve in wallet (your owner slot ${esc(mySlot.slot)})</button></div>`
          : "") +
        (request.action === "succession" && request.state === "AUTHORIZED" && successionSignerOf(request, orgRoot) && state.xonly && successionSignerOf(request, orgRoot) === String(state.xonly).toLowerCase() // UX-10: the PINNED successor resumes the durable request
          ? `<div class="actions"><button id="v4-orgroot-signsuccession" class="primary">Approve in wallet (designated successor)</button><div class="f-help">This is the same succession request you started; approving it again does not create a second one.</div></div>`
          : "") +
        rootUI.renderRequestReviewHtml(request) +
        `<details class="adv"><summary>Import another owner's signed approval (paste JSON)</summary><div class="f" style="margin-top:0.4rem"><label class="f-label" for="v4-orgroot-import">Signed approval envelope</label>` +
        `<textarea id="v4-orgroot-import" rows="3" class="mono"></textarea>` +
        `<div class="f-help">Approvals collected on another device are pasted here. PolicyVault checks the envelope against this exact request before anything is stored.</div>` +
        `<button type="button" id="v4-orgroot-import-btn">Import approval</button></div></details>` +
        `<div class="modal-actions"><button id="v4-orgroot-request-close">Close</button></div></div>`;
      m.style.display = "flex";
      $("v4-orgroot-request-close").onclick = () => { m.style.display = "none"; render(); };
      const succBtn = $("v4-orgroot-signsuccession");
      if (succBtn) succBtn.onclick = async () => { succBtn.disabled = true; await signSuccessionRequest(rootUI, orgRoot, request, state.address); };
      const signBtn = $("v4-orgroot-signmyslot");
      if (signBtn) signBtn.onclick = async () => {
        signBtn.disabled = true;
        try {
          if (!s.ready || !s.adapter) throw Object.assign(new Error(`wallet is not connected on ${networkLabel()}`), { code: "WALLET_NOT_READY" });
          if (request.state !== "AUTHORIZED") throw Object.assign(new Error(`this request is ${request.state} — owner approvals are only collected while it is AUTHORIZED`), { code: "REQUEST_NOT_SIGNABLE" }); // rc16 review N-02
          note(`Fetching your owner slot ${mySlot.slot} signing request…`, "warn");
          const slotEnvelope = await rootUI.fetchSlotRequest(orgRoot.rootCovenantId, requestId, mySlot.slot);
          note("Waiting for your wallet — review and approve your owner signature…", "warn");
          const response = await rootUI.signOwnSlot({
            request, slotEnvelope, adapter: s.adapter, connectedXOnly: state.xonly, network: s.network, expectedSignerAddress: state.address
          });
          await rootUI.postSlotSignature(orgRoot.rootCovenantId, requestId, mySlot.slot, response);
          note(`Your approval (owner slot ${mySlot.slot}) was recorded. This is not yet a transaction — the request needs all required approvals, then finalize and submit.`, "good");
        } catch (err) { noteRootRefusal("Approval did not complete — nothing was sent", err, rootUI); }
        repaint();
      };
      const importBtn = $("v4-orgroot-import-btn");
      if (importBtn) importBtn.onclick = async () => {
        const raw = $("v4-orgroot-import").value;
        const v = rootUI.validateImportedEnvelope(request, raw);
        if (!v.ok) { noteRootRefusal("Import refused", Object.assign(new Error(v.message), { code: v.code }), rootUI); return; }
        try {
          await rootUI.postSlotSignature(orgRoot.rootCovenantId, requestId, v.slot, v.response);
          note(`Imported the approval for owner slot ${v.slot}.`, "good");
        } catch (err) { noteRootRefusal("Import failed", err, rootUI); }
        repaint();
      };
      const finBtn = m.querySelector("[data-rootfinalize]");
      if (finBtn) finBtn.onclick = async () => {
        finBtn.disabled = true;
        try {
          if (!s.ready || !s.adapter) throw Object.assign(new Error(`wallet is not connected on ${networkLabel()}`), { code: "WALLET_NOT_READY" });
          note("Waiting for your wallet — approve the network-fee input signature…", "warn");
          const res = await rootUI.finalizeRequest(orgRoot.rootCovenantId, requestId, request, { adapter: s.adapter, network: s.network, expectedSignerAddress: state.address, connectedXOnly: state.xonly });
          note(`Finalized — ${res.request.state}. Not yet broadcast: use Submit to send it to ${networkLabel()}.`, "good");
        } catch (err) { noteRootRefusal("Finalize did not complete — nothing was sent", err, rootUI); }
        repaint();
      };
      const subBtn = m.querySelector("[data-rootsubmit]");
      if (subBtn) subBtn.onclick = async () => {
        subBtn.disabled = true;
        try {
          const res = await rootUI.submitRequest(orgRoot.rootCovenantId, requestId, request);
          noteOutcome(rootUI.actionLabel(request.action || request.kind), res.request.state, res.txId, res.request.error);
        } catch (err) { noteRootRefusal("Submit failed — outcome uncertain; use Verify state on the root before submitting again", err, rootUI); }
        repaint();
      };
      /* F-6: withdrawal is offered only for an unsigned, never-attempted request (org-root-ui withdrawEligibility); the
       * server re-decides (CANNOT_REJECT otherwise). A failed, refused or unknown result is shown as such and the request
       * stays open — success is claimed only from the server's own REFUSED answer. */
      const rejBtn = m.querySelector("[data-rootreject]");
      if (rejBtn) rejBtn.onclick = async () => {
        if (!window.confirm("Withdraw this request?\n\nIt is unsigned and was never sent: withdrawing releases only this request's reservation of the root (and of the vault it names). Nothing is broadcast; the root is unchanged.")) return;
        rejBtn.disabled = true;
        let outcome = null;
        try { outcome = await rootUI.rejectRequest(orgRoot.rootCovenantId, requestId, "withdrawn by an owner"); }
        catch (err) { noteRootRefusal("Withdraw did not complete — the request and its reservation are kept", err, rootUI); repaint(); return; }
        const st = outcome && outcome.request ? outcome.request.state : null;
        if (st === "REFUSED") { note("Request withdrawn: its reservation is released; the root is unchanged.", "good"); m.style.display = "none"; render(); return; }
        note(`Withdraw returned an unexpected result (${st || "no request state"}) — treated as NOT withdrawn; reload to see the durable state.`, "bad");
        repaint();
      };
      /* F-6: an attempted / uncertain request's ONLY path is outcome recovery — the same root reconciliation as Verify state. */
      const recBtn = m.querySelector("[data-rootreconcile-request]");
      if (recBtn) recBtn.onclick = async () => {
        recBtn.disabled = true;
        try {
          const res = await rootUI.reconcileRoot(orgRoot.rootCovenantId);
          const d = rootUI.describeReconcileOutcome(res);
          note(d.text, d.level);
        } catch (err) { noteRootRefusal("Verify state failed — the outcome stays unknown", err, rootUI); }
        repaint();
      };
    }
    await repaint();
  }

  /* ===================== ACTIVITY (first-class audit surface) =============
   * Durable audit events, clearly separated into CHAIN events (transactions
   * verified against Kaspa) and METADATA events (off-chain application data
   * — organizations/assignments — which are NEVER chain-enforced). */
  async function renderActivityView(root, stale = () => false) {
    await renderRetained(root, stale, {
      view: "activity",
      what: "activity",
      signInWhat: "Sign in to view activity.",
      fetchData: async () => {
        const { events = [] } = await getJSON("/audit?limit=300");
        return { events };
      },
      paint: paintActivityView
    });
  }

  function paintActivityView(root, { events }, refreshing) {
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
      (refreshing ? refreshingChip : "") +
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


  /* ===================== SPEND (delegated request) =====================
   * TRACK 11, finding D1 (HIGH). The delegated spend — the most-used
   * action in the product — used to be a chain of two window.prompt()
   * dialogs: "Recipient wallet address (must be in this agent's
   * allowlist):" followed by "Spend amount (KAS):". That is an adoption
   * failure three times over: the allowlist the first prompt refers to
   * was never shown, so the user had to already know an allowed address
   * by heart; nothing was validated against the agent's own limits until
   * the server refused; and a native prompt chain has no labels, no
   * error recovery, and nothing to read on a 375 px screen.
   *
   * This is the same flow with a real form. It is PRESENTATION AND
   * DEFENSE-IN-DEPTH ONLY:
   *   - the recipient options are the vault presentation's own
   *     recipientAddresses (the allowlist the covenant commits to), and
   *     the chosen ADDRESS is still resolved through the server's one
   *     address-identity boundary — the browser never substitutes a
   *     paired x-only for the address the human read;
   *   - the local amount checks mirror limits the covenant enforces and
   *     the server re-derives; they can only REFUSE EARLIER, never
   *     permit. Every one of them is repeated authoritatively downstream;
   *   - it ends in the identical runFlow(vaultId, "agentSpend", ...) call
   *     with the identical params, so review, browser verification, the
   *     approvals workflow and signing are untouched.
   */
  function spendFormHtml(vault, agent) {
    const allow = Array.isArray(agent.recipientAddresses) ? agent.recipientAddresses : [];
    const recipientField = allow.length
      ? `<label for="v4-spend-to">Pay</label>` +
        `<select id="v4-spend-to" name="to">` +
        allow.map((a, i) => `<option value="${esc(a)}"${i === 0 ? " selected" : ""}>${esc(a)}</option>`).join("") +
        `</select>` +
        `<div class="hint">Only these addresses are payable by this agent — the allowlist is committed on-chain and enforced by the covenant.</div>`
      : `<label for="v4-spend-to">Pay (wallet address)</label>` +
        `<input id="v4-spend-to" name="to" class="mono" placeholder="${addrExample()}" autocomplete="off" />` +
        `<div class="hint">This vault view did not include the agent's allowed recipients, so the address cannot be offered as a choice here. The covenant still enforces the allowlist: an address outside it is refused.</div>`;
    return (
      `<div class="modal-card" style="max-width:560px;width:92%" role="dialog" aria-modal="true" aria-labelledby="v4-spend-title">` +
      `<h3 id="v4-spend-title" style="margin-top:0">Send from ${esc(vault.label || short(vault.vaultId))}</h3>` +
      `<div class="kv-line">Signing as this vault's agent <span class="mono">${esc(state.address)}</span></div>` +
      `<div class="grid" style="margin:0.6rem 0">` +
      `<div class="field"><div class="k">Max per transaction</div><div class="v">${esc(agent.maxPerSpendKas)} KAS</div></div>` +
      `<div class="field"><div class="k">Remaining this period</div><div class="v">${esc(agent.remainingBudgetKas)} KAS</div></div>` +
      `<div class="field"><div class="k">Approval required above</div><div class="v">${esc(agent.approvalThresholdKas)} KAS</div></div>` +
      `</div>` +
      `<form class="cform" id="v4-spend-form" autocomplete="off" novalidate>` +
      `<div class="full">${recipientField}${ferr("to")}</div>` +
      `<div class="full"><label for="v4-spend-amount">Amount (KAS)</label>` +
      `<input id="v4-spend-amount" name="amount" inputmode="decimal" placeholder="0.00" />${ferr("amount")}` +
      `<div class="hint" id="v4-spend-note"></div></div>` +
      `<div class="full modal-actions"><button type="button" id="v4-spend-cancel">Cancel</button>` +
      `<button type="submit" class="primary">Review payment…</button></div>` +
      `</form>` +
      `<div class="hint" style="margin-top:0.6rem">These checks are a convenience. Every limit here is enforced by the covenant on Kaspa and re-derived by the server — nothing you enter can raise them.</div>` +
      `</div>`
    );
  }

  /* Local pre-checks. Returns a Map(fieldKey -> {message, inputs}) in the
   * same shape showFieldErrors() already renders for the create form. */
  function validateSpendForm(f, agent) {
    const errors = new Map();
    const bad = (key, message, el) => { if (!errors.has(key)) errors.set(key, { message, inputs: [el].filter(Boolean) }); };
    const toEl = f.querySelector('[name="to"]');
    const amtEl = f.querySelector('[name="amount"]');
    const to = (toEl && toEl.value ? String(toEl.value) : "").trim();
    const amountKas = (amtEl && amtEl.value ? String(amtEl.value) : "").trim();
    if (!to) bad("to", "Choose or enter a recipient address.", toEl);
    const sompi = kasToSompiClient(amountKas);
    if (!amountKas) bad("amount", "Enter an amount in KAS.", amtEl);
    else if (sompi === null || BigInt(sompi) <= 0n) bad("amount", "Enter an amount greater than 0 KAS (up to 8 decimal places).", amtEl);
    else {
      const cap = kasToSompiClient(agent.maxPerSpendKas);
      const left = kasToSompiClient(agent.remainingBudgetKas);
      if (cap !== null && BigInt(sompi) > BigInt(cap)) {
        bad("amount", `Above this agent's maximum per transaction (${agent.maxPerSpendKas} KAS). The covenant refuses it.`, amtEl);
      } else if (left !== null && BigInt(sompi) > BigInt(left)) {
        bad("amount", `Above this agent's remaining budget for the current period (${agent.remainingBudgetKas} KAS). The covenant refuses it.`, amtEl);
      }
    }
    return { ok: errors.size === 0, errors, to, sompi };
  }

  /* Live, honest note under the amount: what WILL happen at this value. */
  function spendFormNote(f, vault, agent) {
    const el = $("v4-spend-note");
    if (!el) return;
    const amountKas = (f.querySelector('[name="amount"]')?.value ?? "").trim();
    const sompi = kasToSompiClient(amountKas);
    if (!amountKas || sompi === null || BigInt(sompi) <= 0n) { el.textContent = ""; return; }
    const threshold = kasToSompiClient(agent.approvalThresholdKas);
    const required = Number((vault.live && vault.live.approvalM) || 0);
    if (threshold !== null && BigInt(sompi) > BigInt(threshold)) {
      el.textContent = required > 0
        ? `Above the approval threshold: this creates an approval request needing ${required} approval${required === 1 ? "" : "s"} before you can sign it.`
        : "Above the approval threshold: this vault's approval policy applies before it can be signed.";
    } else {
      el.textContent = "At or below the approval threshold: you can sign this yourself.";
    }
  }

  function openSpendForm(vault, agent) {
    const m = $("v4-modal");
    if (!m) return;
    m.innerHTML = spendFormHtml(vault, agent);
    m.style.display = "flex";
    const close = () => { m.style.display = "none"; };
    const cancel = $("v4-spend-cancel");
    if (cancel) cancel.onclick = close;
    const f = $("v4-spend-form");
    if (!f) return;
    const first = f.querySelector('[name="to"]');
    if (first && typeof first.focus === "function") { try { first.focus(); } catch { /* focus is a nicety */ } }
    f.addEventListener("input", () => spendFormNote(f, vault, agent));
    f.addEventListener("change", () => spendFormNote(f, vault, agent));
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = f.querySelector('button[type="submit"]');
      const { ok, errors, to, sompi } = validateSpendForm(f, agent);
      showFieldErrors(f, errors);
      if (!ok) return;
      if (submitBtn) submitBtn.disabled = true;
      try {
        // The chosen ADDRESS is resolved through the server's one
        // address-identity boundary, exactly as the typed address was:
        // the identity that gets spent to is derived from the string the
        // human read, never from a pairing this browser was handed.
        let recipientX;
        try { recipientX = await resolveXOnly(to); }
        catch (err) { showFieldErrors(f, new Map([["to", { message: `Recipient address rejected: ${err.message}`, inputs: [f.querySelector('[name="to"]')] }]])); return; }
        close();
        await runFlow(vault.vaultId, "agentSpend", { agentPk: agent.agentPk, recipient: recipientX, payAmountSompi: sompi }, "Sign spend");
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  function wireVault(root) {
    root.querySelectorAll("[data-spend]").forEach((b) => (b.onclick = () => {
      const agentPk = b.getAttribute("data-spend");
      const vaultId = b.closest("[data-vault]").getAttribute("data-vault");
      const vault = state.vaultsById[vaultId];
      const agent = vault && (vault.agents || []).find((a) => a.agentPk === agentPk);
      // Fail closed on display too: without the agent's own presented
      // policy there is nothing truthful to show, so nothing is offered.
      if (!vault || !agent) { note("This agent's current policy is not loaded — reload before spending.", "bad"); render(); return; }
      openSpendForm(vault, agent);
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
    root.querySelectorAll("[data-pause]").forEach((b) => (b.onclick = async () => {
      if (!window.confirm("Pause this vault?\n\nEvery agent's payments stop immediately once the pause is confirmed on-chain — this is the covenant's own pause, enforced on Kaspa. You review and sign the transaction in your wallet. Unpause any time.")) return;
      const p = await withFuel({}); if (p) runFlow(vid(b), "ownerPause", p, "Approve in wallet");
    }));
    root.querySelectorAll("[data-unpause]").forEach((b) => (b.onclick = async () => { const p = await withFuel({}); if (p) runFlow(vid(b), "ownerUnpause", p, "Approve in wallet"); }));
    // ---- hosted agent suspend/unsuspend (surface 21; coordination-only) ----
    root.querySelectorAll("[data-suspend]").forEach((b) => (b.onclick = () => suspendUpdate(vid(b), { op: "suspend", agentPk: b.getAttribute("data-suspend") })));
    root.querySelectorAll("[data-unsuspend]").forEach((b) => (b.onclick = () => suspendUpdate(vid(b), { op: "unsuspend", agentPk: b.getAttribute("data-unsuspend") })));
    root.querySelectorAll("[data-suspendall]").forEach((b) => (b.onclick = () => suspendUpdate(b.getAttribute("data-suspendall"), { op: "suspend", allAgents: true })));
    root.querySelectorAll("[data-unsuspendall]").forEach((b) => (b.onclick = () => suspendUpdate(b.getAttribute("data-unsuspendall"), { op: "unsuspend", allAgents: true })));
    /* Top-ups: a labelled amount form (no native prompt), through the same
     * fuel-funded owner flow. The deposit and the reserve are explained
     * where the amount is entered. */
    root.querySelectorAll("[data-topup]").forEach((b) => (b.onclick = () => openAmountForm({
      title: "Top up the deposit",
      label: "Amount to add to the deposit",
      help: "Adds KAS to the protected deposit the agents may spend under the vault's rules. Only the owner can take it back (Close & recover). The network fee comes from your wallet, not from the vault.",
      onSubmit: async (sompi) => { const p = await withFuel({ topUpAmountSompi: sompi }); if (p) runFlow(vid(b), "ownerTopUp", p, "Approve in wallet"); }
    })));
    root.querySelectorAll("[data-topupreserve]").forEach((b) => (b.onclick = () => openAmountForm({
      title: "Top up the fee reserve",
      label: "Amount to add to the fee reserve",
      help: "The fee reserve pays the network fee of each agent payment so the deposit is never reduced by fees. When it is used up, agent payments made through PolicyVault stop until it is topped up.",
      onSubmit: async (sompi) => { const p = await withFuel({ topUpReserveAmountSompi: sompi }); if (p) runFlow(vid(b), "ownerTopUpReserve", p, "Approve in wallet"); }
    })));
    /* Owner recovery is TERMINAL and moves every remaining sompi. The old
     * confirmation ("Close and recover this vault? This is terminal.")
     * named neither the destination, the amount, nor the effect on the
     * vault's agents — for the one irreversible funds operation an owner
     * can take (TRACK 11, finding W1). "Vault recovery" transfers the
     * vault's funds; it is NOT the organizational root's "recover control"
     * (a governance change) — the two are named differently on purpose. */
    root.querySelectorAll("[data-recover]").forEach((b) => (b.onclick = async () => {
      const v = state.vaultsById[vid(b)];
      const amount = v && v.live && v.live.protectedValueKas ? `${v.live.protectedValueKas} KAS of deposit` : "the vault's remaining deposit";
      const reserve = v && v.live && v.live.feeReserveKas ? ` plus the ${v.live.feeReserveKas} KAS fee reserve` : "";
      if (!window.confirm(
        `Close this vault permanently and withdraw ${amount}${reserve} to the owner wallet ${state.address}?\n\n` +
        `This is irreversible. The vault ends: every agent loses access immediately, the policy and its budgets stop existing, ` +
        `and the vault cannot be reopened — a new vault would have to be created and funded.\n\n` +
        `You will review the exact transaction and sign it in your wallet before anything is broadcast.`
      )) return;
      const p = await withFuel({});
      if (p) runFlow(vid(b), "ownerRecover", p, "Approve in wallet");
    }));
    root.querySelectorAll("[data-remove]").forEach((b) => (b.onclick = async () => {
      if (!window.confirm("Remove this agent?\n\nThe agent loses the ability to pay from this vault once the change is confirmed on-chain. Its remaining budget disappears with it. You review and sign the transaction in your wallet.")) return;
      const p = await withFuel({ agentPk: b.getAttribute("data-remove") }); if (p) runFlow(vid(b), "removeAgent", p, "Approve in wallet");
    }));
    root.querySelectorAll("[data-verify]").forEach((b) => (b.onclick = async () => {
      try { const r = await postJSON(`/vaults/${vid(b)}/reconcile`, {}); note(`Verify state: ${r.reconcile.status}`, "good"); render(); } catch (e) { note(`Verify state failed: ${e.message}`, "bad"); }
    }));
    // Add agent / change an agent's rules / rotate an agent's key: the SAME
    // agent-policy form the vault setup uses (no prompt chains, no
    // comma-delimited lists, no DAA entry). An existing agent's exact
    // budget period is kept unchanged unless deliberately edited.
    root.querySelectorAll("[data-addagent]").forEach((b) => (b.onclick = () => openAgentPolicyForm({ vault: state.vaultsById[vid(b)], mode: "add" })));
    root.querySelectorAll("[data-repolicy]").forEach((b) => (b.onclick = () => openAgentPolicyForm({ vault: state.vaultsById[vid(b)], mode: "repolicy", agentPk: b.getAttribute("data-repolicy") })));
    root.querySelectorAll("[data-rotate]").forEach((b) => (b.onclick = () => openAgentPolicyForm({ vault: state.vaultsById[vid(b)], mode: "rotate", agentPk: b.getAttribute("data-rotate") })));
    root.querySelectorAll("[data-setapprovers]").forEach((b) => (b.onclick = () => openSetApproversForm(state.vaultsById[vid(b)])));
  }

  /* ===================== OWNER ACTION FORMS (shared components) ==========
   * Replace the former window.prompt chains (add agent = 5 prompts, set
   * approvers = comma-separated addresses + "Required approvals (M)",
   * top-ups) with the same labelled, validated components the guided
   * setup uses. Presentation and defense-in-depth only: every value is
   * re-derived by the server and enforced by the covenant; each flow ends
   * in the identical runFlow(...) call with the identical params.
   * ====================================================================== */

  function openAmountForm({ title, label, help, onSubmit }) {
    const su = setupUi();
    const m = $("v4-modal");
    if (!su || !m) { note("The setup components did not load in this build — reload the page.", "bad"); return; }
    m.innerHTML =
      `<div class="modal-card setup-card" role="dialog" aria-modal="true" aria-labelledby="v4-amount-title"><h3 id="v4-amount-title" style="margin-top:0">${esc(title)}</h3>` +
      `<form class="setup-form" id="v4-amount-form" autocomplete="off" novalidate>` +
      su.renderField({ name: "amount", label, control: su.kasInput({ name: "amount", placeholder: "0.00" }), help: esc(help), wide: true }) +
      `<div class="modal-actions"><button type="button" id="v4-amount-cancel">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="primary">Review…</button></div></form></div>`;
    m.style.display = "flex";
    $("v4-amount-cancel").onclick = () => { m.style.display = "none"; };
    const f = $("v4-amount-form");
    const first = f.querySelector('[name="amount"]');
    if (first && typeof first.focus === "function") { try { first.focus(); } catch { /* nicety */ } }
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const sompi = su.kasToSompi(f.querySelector('[name="amount"]')?.value ?? "");
      if (sompi === null || BigInt(sompi) <= 0n) { showFieldErrors(f, new Map([["amount", "Enter a KAS amount greater than 0 (up to 8 decimals)."]])); return; }
      m.style.display = "none";
      await onSubmit(sompi);
    });
  }

  /* Agent policy form for add / change rules / rotate key. Prefilled from
   * the presented agent (exact values: the live periodLengthDaa is offered
   * as "Keep current value" and round-trips UNCHANGED unless edited). */
  function openAgentPolicyForm({ vault, mode, agentPk }) {
    const su = setupUi();
    const m = $("v4-modal");
    if (!su || !m || !vault) { note("This vault's current state is not loaded — reload before changing it.", "bad"); return; }
    const existing = agentPk ? (vault.agents || []).find((a) => a.agentPk === agentPk) : null;
    if (mode !== "add" && !existing) { note("This agent's current policy is not loaded — reload before changing it.", "bad"); return; }
    const titles = { add: "Add an agent", repolicy: "Change this agent's rules", rotate: "Rotate this agent's key" };
    const draft = {
      agent: mode === "repolicy" ? (existing.agentAddress || "") : "",
      recipients: existing && Array.isArray(existing.recipientAddresses) && existing.recipientAddresses.length ? existing.recipientAddresses.map((a) => ({ address: a })) : [{ address: "" }],
      maxPerSpend: existing ? existing.maxPerSpendKas : "",
      budget: existing ? existing.periodBudgetKas : "",
      period: existing && existing.periodLengthDaa ? { preset: "existing", customValue: "", customUnit: "day", existingDaa: existing.periodLengthDaa } : { preset: su.BUDGET_SETTING.defaultPreset, customValue: "", customUnit: "day" },
      approvalThreshold: existing ? existing.approvalThresholdKas : "",
      maxFee: existing && existing.agentMaxFeePerTxKas ? existing.agentMaxFeePerTxKas : ""
    };
    let errors = new Map();
    const paint = () => {
      const err = (k) => errors.get(k) || "";
      const rowErr = (k) => errors.get(k) || {};
      const F = su.renderField;
      const agentField = mode === "repolicy"
        ? `<div class="f f-wide"><div class="f-label">Agent wallet</div><div class="addr-display"><span class="mono">${esc(existing.agentAddress || existing.agentPk)}</span></div><div class="f-help">Changing the rules keeps the same agent key. The new rules replace the old ones, and the budget period restarts from the network position at which the change is built (not from its confirmation).</div></div>`
        : F({ name: "agent", label: mode === "rotate" ? "New agent wallet" : "Agent wallet", control: su.textInput({ name: "agent", value: draft.agent, placeholder: addrExample(), mono: true }), help: mode === "rotate" ? `Replaces the agent key <span class="mono">${esc(existing.agentAddress || existing.agentPk)}</span>. The old key loses access once the change is confirmed on-chain; the rules below apply to the new key.` : "The wallet allowed to make payments from this vault within the rules below. It cannot change the rules and cannot act as the owner.", error: err("agent"), wide: true });
      m.innerHTML =
        `<div class="modal-card setup-card" role="dialog" aria-modal="true" aria-labelledby="v4-agent-title"><h3 id="v4-agent-title" style="margin-top:0">${esc(titles[mode])}</h3>` +
        `<div class="f-help">Vault ${esc(vault.label || short(vault.vaultId))}. The owner (you) authorizes this change by signing; the covenant enforces the new rules on every payment.</div>` +
        `<form class="setup-form" id="v4-agent-form" autocomplete="off" novalidate>` +
        agentField +
        `<div class="f f-wide${err("recipients") ? " f-invalid" : ""}" data-field="recipients"><div class="f-label">Allowed recipients</div>` +
        su.renderAddressRows({ kind: "recipient", rows: draft.recipients, errors: rowErr("recipientRows"), addLabel: "Add recipient", placeholder: addrExample() }) +
        `<div class="f-help">Wallets this agent is allowed to pay — enforced by the covenant on Kaspa.</div><div class="ferr" data-err="recipients"${err("recipients") ? ' style="display:block"' : ""}>${esc(err("recipients"))}</div></div>` +
        `<div class="f-grid">` +
        F({ name: "maxPerSpend", label: "Maximum per payment", control: su.kasInput({ name: "maxPerSpend", value: draft.maxPerSpend, placeholder: "2" }), help: "The most the agent may send in one payment.", error: err("maxPerSpend") }) +
        F({ name: "budget", label: "Spending budget", control: su.kasInput({ name: "budget", value: draft.budget, placeholder: "10" }), help: "The most the agent may send in total during one budget period.", error: err("budget") }) +
        `</div>` +
        F({ name: "period", label: "Budget period", control: su.renderDurationControl({ name: "period", setting: su.BUDGET_SETTING, selection: draft.period }), help: `${su.COPY.BUDGET_WINDOW} ${su.COPY.UNITS}`, error: err("period"), wide: true }) +
        F({ name: "approvalThreshold", label: "Payments that need extra approval", control: su.kasInput({ name: "approvalThreshold", value: draft.approvalThreshold, placeholder: "1" }), help: `Payments <b>above</b> this amount need the vault's approvers (${esc(String(vault.live && vault.live.approvalM || "0"))} of ${(vault.approverSlots || []).filter((s) => s !== "00".repeat(32)).length} currently) to sign first; at or below it the agent signs alone.`, error: err("approvalThreshold"), wide: true }) +
        `<details class="adv"><summary>Advanced</summary>` + F({ name: "maxFee", label: "Maximum network fee per payment", control: su.kasInput({ name: "maxFee", value: draft.maxFee, placeholder: "0.10" }), help: "Caps the fee a single payment may take from the fee reserve. Optional (default 0.10 KAS).", error: err("maxFee"), optional: true }) + `</details>` +
        su.renderLiveSummary(su.vaultRulesSummary({ ...draft, approvers: [], approvalM: "" }), "v4-agent-summary") +
        `<div class="modal-actions"><button type="button" id="v4-agent-cancel">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="primary">Review…</button></div></form></div>`;
      m.style.display = "flex";
      const f = $("v4-agent-form");
      const read = () => {
        const val = (n) => f.querySelector(`[name="${n}"]`)?.value ?? draft[n] ?? "";
        if (mode !== "repolicy") draft.agent = val("agent");
        draft.maxPerSpend = val("maxPerSpend"); draft.budget = val("budget"); draft.approvalThreshold = val("approvalThreshold"); draft.maxFee = val("maxFee");
        const sel = f.querySelector('[name="period"]');
        if (sel) draft.period = { preset: sel.value, customValue: f.querySelector('[name="periodValue"]')?.value ?? "", customUnit: f.querySelector('[name="periodUnit"]')?.value ?? "day", existingDaa: draft.period.existingDaa };
        const rowsEl = f.querySelector('[data-rows="recipient"]');
        if (rowsEl) { const rows = [...rowsEl.querySelectorAll(".addr-row")].map((row) => ({ address: row.querySelector('[name="recipient"]')?.value ?? "" })); draft.recipients = rows.length ? rows : [{ address: "" }]; }
      };
      const sync = () => {
        read();
        const sel = f.querySelector('[name="period"]'); const custom = f.querySelector('[data-duration-custom="period"]');
        if (sel && custom) custom.hidden = sel.value !== "custom";
        const eff = f.querySelector('[data-duration-effect="period"]'); if (eff) eff.textContent = su.durationEffectText(su.BUDGET_SETTING, draft.period);
        const exact = f.querySelector('[data-duration-exact="period"]'); if (exact) exact.textContent = su.durationExactText(su.BUDGET_SETTING, draft.period);
        const summary = $("v4-agent-summary"); if (summary) summary.outerHTML = su.renderLiveSummary(su.vaultRulesSummary({ ...draft, approvers: [], approvalM: "" }), "v4-agent-summary");
      };
      f.addEventListener("input", sync); f.addEventListener("change", sync); sync();
      $("v4-agent-cancel").onclick = () => { m.style.display = "none"; };
      m.querySelectorAll("button").forEach((b) => {
        if (b.id === "v4-add-recipient") b.onclick = (e) => { e.preventDefault(); read(); draft.recipients.push({ address: "" }); errors.delete("recipients"); errors.delete("recipientRows"); paint(); };
        else if (b.classList.contains("rm-recipient")) b.onclick = (e) => { e.preventDefault(); read(); const i = Number(b.closest(".addr-row")?.getAttribute("data-row")); if (draft.recipients.length > 1) draft.recipients.splice(i, 1); errors.delete("recipients"); errors.delete("recipientRows"); paint(); };
      });
      f.addEventListener("submit", async (e) => {
        e.preventDefault();
        read();
        const submitBtn = f.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        try {
          const d = { ...draft, agent: mode === "repolicy" ? (existing.agentAddress || "") : draft.agent, approvers: [], approvalM: "", label: "x", deposit: "1", reserve: "0" };
          const stepsToCheck = ["agent", "rules"];
          let bad = false;
          errors = new Map();
          // UX-04: validate against the vault's ACTUAL approver configuration
          // (this change never touches approvers; a 0 KAS threshold is valid
          // exactly when the vault has payment approvers)
          const sentinel0 = "00".repeat(32);
          const existingApprovers = { count: (vault.approverSlots || []).filter((x) => x !== sentinel0).length, approvalM: vault.live && vault.live.approvalM ? String(vault.live.approvalM) : "0" };
          for (const st of stepsToCheck) {
            const { errors: errs } = await su.validateVaultDraft(d, { resolve: resolveXOnly, step: st, existingApprovers });
            for (const [k, v] of errs) { errors.set(k, v); bad = true; }
          }
          // repolicy: an agent whose presentation lacks an address still resolves through agentPk
          if (mode === "repolicy" && errors.get("agent") && !existing.agentAddress) { errors.delete("agent"); bad = [...errors.keys()].length > 0; }
          if (bad) { paint(); note("Fix the highlighted fields, then continue.", "bad"); return; }
          const full = await su.validateVaultDraft(d, { resolve: resolveXOnly, signerAddress: state.address, vaultId: vault.vaultId, existingApprovers });
          if (!full.ok) { errors = full.errors; paint(); note("Fix the highlighted fields, then continue.", "bad"); return; }
          const n = full.normalized;
          const agentPkResolved = mode === "repolicy" ? existing.agentPk : n.agentXOnly;
          const { virtualDaaScore } = await getJSON("/network/status");
          const agent = {
            agentPk: agentPkResolved,
            maxPerSpend: su.kasToSompi(n.maxPerSpendKas),
            periodBudget: su.kasToSompi(n.budgetKas),
            periodLengthDaa: n.period.daa,
            periodStartDaa: String(virtualDaaScore),
            periodSpent: "0",
            approvalThreshold: su.kasToSompi(n.approvalThresholdKas),
            agentMaxFeePerTx: su.kasToSompi(n.maxFeeKas || "0.10"),
            recipients: n.recipientXOnlys
          };
          m.style.display = "none";
          const p = await withFuel(mode === "add" ? { agent } : { agentPk: existing.agentPk, agent });
          if (!p) return;
          const action = mode === "add" ? "addAgent" : mode === "repolicy" ? "rePolicyAgent" : "rotateAgent";
          runFlow(vault.vaultId, action, p, "Approve in wallet");
        } catch (err) {
          noteRefusal(`${titles[mode]} refused`, err);
        } finally {
          if (submitBtn) submitBtn.disabled = false;
        }
      });
    };
    paint();
  }

  /* Set payment approvers: rows + "k of N approvers" (no comma-separated
   * prompt, no "(M)"). The current approvers are shown by address when the
   * server presents them, and the count is never lowered on the user's
   * behalf when a row is removed. */
  function openSetApproversForm(vault) {
    const su = setupUi();
    const m = $("v4-modal");
    if (!su || !m || !vault) { note("This vault's current state is not loaded — reload before changing it.", "bad"); return; }
    const sentinel = "00".repeat(32);
    const currentAddrs = Array.isArray(vault.approverAddresses) ? vault.approverAddresses.filter(Boolean) : [];
    const currentCount = (vault.approverSlots || []).filter((s) => s !== sentinel).length;
    const draft = { approvers: currentAddrs.length ? currentAddrs.map((a) => ({ address: a })) : [], approvalM: vault.live && vault.live.approvalM ? String(vault.live.approvalM) : "" };
    let errors = new Map();
    const paint = () => {
      const err = (k) => errors.get(k) || "";
      const count = draft.approvers.filter((r) => r.address && r.address.trim()).length;
      m.innerHTML =
        `<div class="modal-card setup-card" role="dialog" aria-modal="true" aria-labelledby="v4-appr-title"><h3 id="v4-appr-title" style="margin-top:0">Set payment approvers</h3>` +
        `<div class="f-help">Vault ${esc(vault.label || short(vault.vaultId))} — currently ${esc(String(vault.live && vault.live.approvalM || "0"))} of ${currentCount} approvers${currentCount && !currentAddrs.length ? " (their addresses are not in this vault view; enter the full new list)" : ""}. Approvers can approve or refuse a payment above an agent's threshold; they cannot spend, and they cannot act as the owner. The new list REPLACES the old one.</div>` +
        `<form class="setup-form" id="v4-appr-form" autocomplete="off" novalidate>` +
        `<div class="f f-wide${err("approvers") ? " f-invalid" : ""}" data-field="approvers"><div class="f-label">Payment approvers</div>` +
        su.renderAddressRows({ kind: "approver", rows: draft.approvers, errors: errors.get("approverRows") || {}, addLabel: "Add approver", placeholder: addrExample(), min: 0, max: MAX_APPROVER_ROWS }) +
        `<div class="f-help">At most 10, each a distinct wallet. Once a vault has payment approvers, the protocol (v0.4.1) cannot take it back to having none — at least one approver must remain. A vault created without approvers can add some here.</div>` +
        `<div class="ferr" data-err="approvers"${err("approvers") ? ' style="display:block"' : ""}>${esc(err("approvers"))}</div></div>` +
        su.renderField({ name: "approvalM", label: "Approvals needed", control: su.renderApprovalSelect({ name: "approvalM", count, value: draft.approvalM, noun: "approvers", max: MAX_APPROVER_ROWS }), help: count ? `How many of the ${count} approvers must sign a payment above the threshold. If you removed an approver, this number was not changed for you — choose it deliberately.` : "Add approvers above to choose how many must sign.", error: err("approvalM") }) +
        `<div class="modal-actions"><button type="button" id="v4-appr-cancel">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="primary">Review…</button></div></form></div>`;
      m.style.display = "flex";
      const f = $("v4-appr-form");
      const read = () => {
        const rowsEl = f.querySelector('[data-rows="approver"]');
        if (rowsEl) draft.approvers = [...rowsEl.querySelectorAll(".addr-row")].map((row) => ({ address: row.querySelector('[name="approver"]')?.value ?? "" }));
        draft.approvalM = f.querySelector('[name="approvalM"]')?.value ?? draft.approvalM;
      };
      const sync = () => {
        read();
        const mSel = f.querySelector('[name="approvalM"]');
        if (!mSel) return;
        const count2 = draft.approvers.filter((r) => r.address && r.address.trim()).length;
        const current = mSel.value;
        const options = su.approvalOptions(count2, "approvers", { max: MAX_APPROVER_ROWS });
        if (current && !options.some((o) => o.value === current)) options.unshift({ value: current, label: `${current} of ${count2} approvers — impossible, choose again` });
        if (!options.length) options.push({ value: "", label: "add approvers first" });
        mSel.innerHTML = options.map((o) => `<option value="${esc(o.value)}"${o.value === current ? " selected" : ""}>${esc(o.label)}</option>`).join("");
        if (!current && options[0]) mSel.value = options[0].value;
      };
      f.addEventListener("input", sync); f.addEventListener("change", sync); sync();
      $("v4-appr-cancel").onclick = () => { m.style.display = "none"; };
      m.querySelectorAll("button").forEach((b) => {
        if (b.id === "v4-add-approver") b.onclick = (e) => { e.preventDefault(); read(); if (draft.approvers.length < MAX_APPROVER_ROWS) draft.approvers.push({ address: "" }); errors = new Map(); paint(); };
        else if (b.classList.contains("rm-approver")) b.onclick = (e) => { e.preventDefault(); read(); const i = Number(b.closest(".addr-row")?.getAttribute("data-row")); if (draft.approvers.length > 1) draft.approvers.splice(i, 1); else { draft.approvers = [{ address: "" }]; errors = new Map([["approvers", "At least one approver must remain: the protocol cannot return a vault to no approvers."]]); } if (draft.approvers.length > 1 || !errors.size) errors = new Map(); paint(); };
      });
      f.addEventListener("submit", async (e) => {
        e.preventDefault();
        read();
        try {
          const d = { ...su.vaultDraftDefaults(), approvers: draft.approvers, approvalM: draft.approvalM, maxPerSpend: "1", budget: "1", approvalThreshold: "1" };
          const { errors: errs } = await su.validateVaultDraft(d, { resolve: resolveXOnly, step: "rules" });
          errors = new Map([...errs].filter(([k]) => k === "approvers" || k === "approverRows" || k === "approvalM"));
          // UX-07: the covenant cannot transition to a zero-approver set
          // (ownerSetApprovers requires 1 <= approvalM <= activeCount) — refuse
          // an empty list HERE instead of promising a removal that would be
          // refused by the core/covenant after the wallet signed.
          if (!draft.approvers.some((r) => r.address && r.address.trim())) errors.set("approvers", "At least one approver is required: the protocol (v0.4.1) cannot return a vault to no approvers after creation.");
          if (errors.size) { paint(); note("Fix the highlighted fields, then continue.", "bad"); return; }
          const approvers = [];
          for (const r of draft.approvers) if (r.address && r.address.trim()) approvers.push(await resolveXOnly(r.address.trim()));
          const approvalM = approvers.length ? String(Number(draft.approvalM)) : "0";
          m.style.display = "none";
          const p = await withFuel({ newApprovers: { approvers, approvalM } });
          if (p) runFlow(vault.vaultId, "ownerSetApprovers", p, "Approve in wallet");
        } catch (err) { noteRefusal("Set approvers refused", err); }
      });
    };
    paint();
  }

  /* Client-side KAS→sompi. The SERVER still re-derives and validates every
   * consensus-visible amount, and the browser verifier still recomputes it
   * before signing — but the client no longer carries its OWN amount grammar:
   * this delegates to core/model/amounts.js `kasToSompi`
   * (`window.PolicyVaultCore.amounts`), the same integer-only parser the SDK,
   * the server and the covenant accounting use, which additionally enforces
   * the canonical MAX_SOMPI ceiling the hand-rolled version lacked. Returns a
   * digit string, or null (fail closed) for anything the canonical grammar
   * refuses. Parity with the previous implementation is pinned vector-by-vector
   * by web/test/client-amounts-parity.test.js. */
  function kasToSompiClient(kas) {
    const core = typeof window !== "undefined" ? window.PolicyVaultCore : undefined;
    if (!core || !core.amounts || typeof core.amounts.kasToSompi !== "function") return null;
    try {
      return core.amounts.kasToSompi(String(kas).trim()).toString();
    } catch {
      return null;
    }
  }

  function navigateTo(view) {
    if (state.view !== view && state.rootBuildRefusal) note("");
    state.view = view;
    render();
  }

  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".v4-tab").forEach((b) => (b.onclick = () => navigateTo(b.dataset.view)));
    // Server-authoritative network label (Gate R: testnet-10 or mainnet) —
    // presentation only (address-example placeholders); every real network
    // check is enforced by the session gate and the server. Shares boot()'s
    // single /health read when app.js exposed it (UX responsiveness pass —
    // startup previously issued three duplicate /health requests).
    (window.PolicyVaultHealthPromise || getJSON("/health")).then((h) => { state.serverNetwork = (h && h.networkId) || null; }).catch(() => { state.serverNetwork = null; });
    // ONE-TIME delegated wiring for create-form row controls, attached to the
    // persistent #v4-root exactly once (never per render): re-renders can no
    // longer stack duplicate listeners, so one click adds exactly one row.
    const root = $("v4-root");
    if (root) root.addEventListener("click", handleCreateRowClick);
    // Same ONE-TIME delegation for the guided setups rendered inside the
    // modal (organizational root): the container persists across renders.
    const modal = $("v4-modal");
    if (modal && typeof modal.addEventListener === "function") modal.addEventListener("click", handleModalSetupClick);
    const supportLink = document.getElementById("footer-support-link");
    if (supportLink) supportLink.onclick = (e) => { e.preventDefault(); navigateTo("support"); window.scrollTo(0, 0); };
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
    _suspendUpdate: suspendUpdate,
    // TRACK 11 spend-form internals (browser test layer only): let the
    // regression suite prove the allowlist rendering, the local limit
    // pre-checks, and that the form still ends in the SAME agentSpend
    // runFlow call with the SAME params.
    _spendFormHtml: spendFormHtml,
    _validateSpendForm: validateSpendForm,
    _openSpendForm: openSpendForm,
    _agentCard: agentCard,
    // Guided setup internals (browser test layer only): the create view,
    // the setup state, the owner action forms, and the funding breakdown.
    _createView: createView,
    _vaultSetup: vaultSetup,
    _readVaultDraft: readVaultDraft,
    _openAgentPolicyForm: openAgentPolicyForm,
    _openSetApproversForm: openSetApproversForm,
    _openAmountForm: openAmountForm,
    _fundingBreakdownHtml: fundingBreakdownHtml,
    _handleCreateRowClick: handleCreateRowClick,
    _handleModalSetupClick: handleModalSetupClick
  };
})();
