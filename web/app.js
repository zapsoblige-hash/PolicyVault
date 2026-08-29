/*
 * PolicyVault dashboard application.
 *
 * Depends ONLY on the generic wallet adapter contract (web/wallet.js) — no
 * KasWare-specific branches in funds-critical logic. All transaction bytes
 * are built/validated server-side by the hardened SDK; the browser supplies
 * user intent and wallet-produced authorization material, and displays the
 * durable request state machine. SUBMITTED is never success — CHAIN VERIFIED
 * is.
 */
/* global PolicyVaultWallet, PolicyVaultIdentity */
(() => {
  const API = "/api/v1";
  // KasWareAdapter (the legacy direct-KasWare implementation) is
  // intentionally NOT destructured here — production code must never
  // construct it; see makeKasWareAdapter's fail-closed replacement below.
  const { WalletState, MockAdapter } = PolicyVaultWallet;

  const ui = {
    state: WalletState.DISCONNECTED,
    adapter: null,
    address: null,
    network: null,
    walletXOnly: null,
    serverNetwork: null,
    vaults: [],
    activeRequest: null,
    orgs: [],
    roleLabels: [],
    assignments: {},
    assignmentsVersion: 0,
    assignmentsError: null,
    selectedOrg: localStorage.getItem("pv.selectedOrg") || "all"
  };

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const shortId = (id) => (id ? id.slice(0, 10) + "…" + id.slice(-6) : "—");
  const kas = (v) => (v === undefined || v === null ? "—" : Number(v).toLocaleString(undefined, { maximumFractionDigits: 8 }));
  // Server-derived network display label — never a hardcoded network name.
  // ui.serverNetwork is set from GET /network/status in boot() below; the
  // fallback phrase is shown only before that resolves. Display-only:
  // every real network check stays on verifyNetwork()'s comparison against
  // ui.serverNetwork (the server's own reported networkId), never a guess.
  const networkLabel = () => ui.serverNetwork || "the configured network";

  async function getJSON(p) {
    const r = await fetch(API + p);
    const j = await r.json();
    if (!r.ok) throw Object.assign(new Error(j.error?.message || r.statusText), { code: j.error?.code, payload: j });
    return j;
  }
  async function postJSON(p, body) {
    const r = await fetch(API + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok) throw Object.assign(new Error(j.error?.message || r.statusText), { code: j.error?.code, payload: j });
    return j;
  }

  /* ---------------- wallet connection state machine ---------------- */

  function setWalletState(state, detail) {
    ui.state = state;
    const el = $("wallet-status");
    const labels = {
      [WalletState.NOT_DETECTED]: "wallet not detected",
      [WalletState.DISCONNECTED]: "disconnected",
      [WalletState.CONNECTING]: "connecting…",
      [WalletState.CONNECTED]: "connected",
      [WalletState.WRONG_NETWORK]: "WRONG NETWORK",
      [WalletState.READY]: "ready",
      [WalletState.ERROR]: "error"
    };
    el.textContent = labels[state] + (detail ? ` — ${detail}` : "");
    el.className = "wstate " + (state === WalletState.READY ? "good" : state === WalletState.WRONG_NETWORK || state === WalletState.ERROR ? "bad" : "");
    $("wallet-address").textContent = ui.address ? ui.address : "—";
    $("wallet-network").textContent = ui.network ?? "—";
    $("wallet-provider").textContent = ui.adapter ? ui.adapter.label : "—";
    $("btn-disconnect").style.display = ui.address ? "" : "none";
    // Owner = the connected wallet, shown as a normal wallet address.
    const ownerEl = $("owner-address");
    if (ownerEl) ownerEl.textContent = ui.address ?? "connect a wallet";
    renderVaults(); // action availability depends on wallet state
    emitWalletChange(); // notify the single canonical session's consumers (e.g. v0.4.1)
  }

  /* ---- Canonical browser wallet session (SINGLE source of truth) ----
   * There is exactly one authoritative wallet session for the whole app. The
   * v0.4.1 module consumes this; it must NOT open a second provider connection.
   * Every wallet change routes through setWalletState -> emitWalletChange. */
  const walletListeners = [];
  function emitWalletChange() {
    const snap = walletSnapshot();
    for (const cb of walletListeners) { try { cb(snap); } catch { /* isolate */ } }
  }
  function walletSnapshot() {
    return {
      connected: !!ui.address,
      ready: ui.state === WalletState.READY,
      address: ui.address ?? null,
      xonly: ui.walletXOnly ?? null,
      network: ui.network ?? null,
      serverNetwork: ui.serverNetwork ?? null,
      provider: ui.adapter ? ui.adapter.label : null,
      adapter: ui.adapter ?? null
    };
  }
  // KasWare connects THROUGH the Universal Signer Interface adapter
  // (web/signer-kasware-adapter.js) ONLY: every signature runs through
  // core/signer executeSigning with its fail-closed capability / scheme /
  // live-network / pre+post-identity gates, and KasWare-specific code lives
  // only in that adapter file.
  //
  // FAIL CLOSED, never bypass (PostLaunchUpgradeOG completion-standard item
  // 4): if the USI adapter module failed to load (a build/deployment
  // defect, an old bundle, a load-order problem — /index.html always loads
  // it, so this should never happen in a correctly served page), this used
  // to silently fall back to the legacy direct-KasWare adapter
  // (web/wallet.js KasWareAdapter), bypassing every one of those gates
  // without any visible sign to the user. That bypass is removed: absence
  // of the USI adapter now returns web/wallet.js's
  // createSigningUnavailableAdapter() stub instead — `detect()` still
  // reflects whether the KasWare extension itself is present (so the UI
  // does not lie and claim "not installed"), but every signing/identity
  // method refuses with USI_UNAVAILABLE, surfaced through the normal
  // WalletState.ERROR path with a message naming the real cause.
  // web/wallet.js's KasWareAdapter class is retained ONLY as the
  // reference/parity fixture for web/test/signer-kasware-adapter.test.js
  // (byte-identical-behavior proof) — production code must never
  // construct it for signing.
  function makeKasWareAdapter() {
    if (window.PolicyVaultKasWareSigner && typeof window.PolicyVaultKasWareSigner.createKasWareSessionAdapter === "function") {
      return window.PolicyVaultKasWareSigner.createKasWareSessionAdapter({ win: window });
    }
    return PolicyVaultWallet.createSigningUnavailableAdapter();
  }
  window.PolicyVaultWalletSession = {
    active: walletSnapshot,
    subscribe(cb) { walletListeners.push(cb); try { cb(walletSnapshot()); } catch { /* isolate */ } return () => { const i = walletListeners.indexOf(cb); if (i >= 0) walletListeners.splice(i, 1); }; },
    connect(kind) { return connectWith(kind === "mock" ? new MockAdapter(API) : makeKasWareAdapter()); },
    disconnect() { return disconnect(); }
  };

  async function verifyNetwork() {
    if (!ui.adapter || !ui.address) return;
    try {
      ui.network = await ui.adapter.getNetwork();
    } catch {
      ui.network = null;
    }
    // The SERVER'S configured network is authoritative (Gate R: testnet-10 or
    // mainnet); the wallet must be on exactly that network. Anything else —
    // including an unknown server network — fails closed to WRONG_NETWORK.
    if (ui.network !== ui.serverNetwork || (ui.serverNetwork !== "testnet-10" && ui.serverNetwork !== "mainnet")) {
      ui.walletXOnly = null;
      setWalletState(WalletState.WRONG_NETWORK, `wallet on ${ui.network ?? "unknown"}, required ${ui.serverNetwork}`);
    } else {
      setWalletState(WalletState.READY);
      // Resolve the connected identity once per connection so vault cards
      // can show only the actions this wallet's ROLE allows (convenience
      // only — the backend independently enforces authorization).
      try {
        ui.walletXOnly = await ui.adapter.getPublicKeyXOnly();
      } catch {
        ui.walletXOnly = null;
      }
      renderVaults();
    }
  }

  /*
   * Advanced details disclosure: read-only covenant identities derived
   * from the addresses the user entered. Never required for normal use.
   */
  function renderAdvancedIdentity(ids, vaultId) {
    const el = $("advanced-identity");
    if (!el) return;
    const lines = [
      `owner x-only: ${ids.owner.xOnlyPubkey}`,
      `delegate x-only: ${ids.delegate.xOnlyPubkey}`,
      ...ids.recipients.map((r, i) => `recipient ${i + 1} x-only: ${r.xOnlyPubkey}`),
      `vault id: ${vaultId}`,
      `network: ${ui.serverNetwork}`
    ];
    el.innerHTML = lines.map((l) => `<div>${esc(l)}</div>`).join("");
  }

  async function connectWith(adapter) {
    ui.adapter = adapter;
    if (!adapter.detect()) {
      setWalletState(WalletState.NOT_DETECTED, adapter.label);
      return;
    }
    setWalletState(WalletState.CONNECTING);
    try {
      const { address } = await adapter.connect();
      ui.address = address;
      adapter.on?.("account", (a) => {
        // Account change invalidates any in-progress signing flow.
        ui.address = a;
        ui.walletXOnly = null; // re-resolved by verifyNetwork for the new account
        if (ui.activeRequest) {
          ui.activeRequest = null;
          closeModal();
          note("Wallet account changed — the in-progress request was discarded. Rebuild it.", "warn");
        }
        verifyNetwork();
      });
      adapter.on?.("network", () => {
        if (ui.activeRequest) {
          ui.activeRequest = null;
          closeModal();
          note("Wallet network changed — the in-progress request was discarded.", "warn");
        }
        verifyNetwork();
      });
      localStorage.setItem("pv.walletProvider", adapter.provider); // convenience only
      await verifyNetwork();
    } catch (e) {
      ui.address = null;
      setWalletState(e.walletCategory === "USER_REJECTED" ? WalletState.DISCONNECTED : WalletState.ERROR, e.message);
    }
  }

  async function disconnect() {
    try {
      await ui.adapter?.disconnect();
    } finally {
      ui.address = null;
      ui.network = null;
      ui.walletXOnly = null;
      setWalletState(WalletState.DISCONNECTED);
    }
  }

  /* ---------------- hosted authentication (Phase B) ----------------
   * WALLET CONNECTED and HOSTED SESSION AUTHENTICATED are different
   * states: connecting a wallet never signs in, and a hosted session
   * grants tenancy identity ONLY — it never signs transactions and never
   * substitutes for owner/agent/approver covenant signatures. The session
   * token lives in an HttpOnly cookie the page cannot read; this module
   * holds only non-secret status. Active only when the server reports
   * authMode enabled (self-hosted servers show nothing). */
  const hostedAuth = { enabled: false, state: "SIGNED_OUT", session: null, boundAddress: null, boundNetwork: null };

  function renderAuth(detail) {
    const btn = $("btn-auth");
    const chip = $("auth-status");
    if (!btn || !chip) return;
    if (!hostedAuth.enabled) {
      btn.style.display = "none";
      chip.style.display = "none";
      return;
    }
    const s = hostedAuth.state;
    const label = {
      SIGNED_OUT: ui.address ? "Wallet connected — not signed in" : "Wallet disconnected",
      SIGNING: "Signing authentication challenge…",
      AUTHENTICATED: `Signed in as ${shortId(hostedAuth.boundAddress)}`,
      EXPIRED: "Session expired — sign in again",
      WALLET_CHANGED: "Wallet changed — sign in again",
      NETWORK_CHANGED: "Network changed — sign in again",
      UNSUPPORTED: "Account type not supported for sign-in"
    }[s] || s;
    chip.style.display = "";
    chip.textContent = label + (detail ? ` — ${detail}` : "");
    btn.style.display = "";
    btn.textContent = s === "AUTHENTICATED" ? "Sign out" : "Sign in";
    btn.disabled = s === "SIGNING" || (s !== "AUTHENTICATED" && ui.state !== WalletState.READY);
  }

  function setAuthState(state, detail) {
    hostedAuth.state = state;
    if (state !== "AUTHENTICATED") { hostedAuth.session = null; }
    renderAuth(detail);
  }

  /* Restore/refresh from the SERVER'S truth (survives reload; §14). A live
   * server session for a DIFFERENT wallet/network than the current browser
   * one is never adopted — the server binding is immutable and the client
   * simply refuses to treat it as usable for the new identity. */
  async function refreshAuthSession() {
    if (!hostedAuth.enabled) return;
    try {
      const s = await getJSON("/auth/session");
      if (!s.authenticated) {
        setAuthState(hostedAuth.state === "AUTHENTICATED" ? "EXPIRED" : "SIGNED_OUT");
        return;
      }
      if (ui.address && (s.walletAddress !== ui.address || s.networkId !== ui.network)) {
        setAuthState(s.walletAddress !== ui.address ? "WALLET_CHANGED" : "NETWORK_CHANGED");
        return;
      }
      hostedAuth.session = s;
      hostedAuth.boundAddress = s.walletAddress;
      hostedAuth.boundNetwork = s.networkId;
      setAuthState("AUTHENTICATED");
    } catch {
      setAuthState("SIGNED_OUT");
    }
  }

  async function hostedSignIn() {
    if (ui.state !== WalletState.READY || !ui.adapter) {
      note("Connect the wallet on the correct network before signing in.", "warn");
      return;
    }
    const forAddress = ui.address;
    const forNetwork = ui.network;
    setAuthState("SIGNING");
    try {
      const { challenge } = await postJSON("/auth/challenge", { walletAddress: forAddress });
      // The wallet extension displays this exact text in its own popup —
      // including "This signature only signs you in. It cannot move funds."
      // Under the USI session adapter the expectations bind the interface's
      // own identity/network gates to THIS sign-in attempt; the legacy
      // adapter ignores the extra argument (same challenge bytes either way).
      const signature = await ui.adapter.signAuthMessage(challenge.message, { expectedSignerAddress: forAddress, network: forNetwork });
      // The wallet may have switched mid-flow: a signature for one identity
      // must never be submitted as another. Fail closed and re-render.
      if (ui.address !== forAddress || ui.network !== forNetwork) {
        setAuthState("WALLET_CHANGED");
        return;
      }
      const publicKey = await ui.adapter.getPublicKeyRaw();
      const res = await postJSON("/auth/verify", { nonce: challenge.nonce, signature, publicKey, walletAddress: forAddress });
      hostedAuth.session = res.session;
      hostedAuth.boundAddress = forAddress;
      hostedAuth.boundNetwork = forNetwork;
      setAuthState("AUTHENTICATED");
    } catch (e) {
      if (e.code === "AUTH_ACCOUNT_TYPE_UNSUPPORTED") {
        setAuthState("UNSUPPORTED");
        note(e.message, "warn");
      } else if (e.walletCategory === "USER_REJECTED") {
        setAuthState("SIGNED_OUT");
        note("Sign-in cancelled.", "warn");
      } else {
        setAuthState("SIGNED_OUT");
        note(`Sign-in failed: ${e.message}`, "warn");
      }
    }
  }

  async function hostedSignOut() {
    try { await postJSON("/auth/logout", {}); } catch { /* server-side expiry also invalidates */ }
    hostedAuth.boundAddress = null;
    hostedAuth.boundNetwork = null;
    setAuthState("SIGNED_OUT");
  }

  /* Wallet account/network switches are SECURITY EVENTS for the hosted
   * session too (§16): the client immediately stops treating the session
   * as usable for the new identity and revokes the old cookie session. */
  walletListeners.push((snap) => {
    if (!hostedAuth.enabled) return;
    if (hostedAuth.state === "AUTHENTICATED") {
      if (snap.address !== hostedAuth.boundAddress) {
        setAuthState("WALLET_CHANGED");
        postJSON("/auth/logout", {}).catch(() => {});
      } else if (snap.network !== hostedAuth.boundNetwork) {
        setAuthState("NETWORK_CHANGED");
        postJSON("/auth/logout", {}).catch(() => {});
      }
    } else {
      renderAuth(); // button enablement follows wallet readiness
    }
  });

  async function initHostedAuth() {
    try {
      const health = await getJSON("/health");
      hostedAuth.enabled = health.authMode === "enabled";
    } catch {
      hostedAuth.enabled = false;
    }
    const btn = $("btn-auth");
    if (btn) btn.onclick = () => (hostedAuth.state === "AUTHENTICATED" ? hostedSignOut() : hostedSignIn());
    if (hostedAuth.enabled) await refreshAuthSession();
    renderAuth();
  }

  /* ---------------- request flow (review -> sign -> progress) ---------------- */

  const PROGRESS_ORDER = ["BUILT", "AWAITING SIGNATURE", "SIGNED", "FINALIZED", "SUBMITTING", "SUBMITTED", "CHAIN_VERIFIED"];

  function progressHtml(current, failed) {
    return `<div class="progress">${PROGRESS_ORDER.map((s) => {
      const active = s === current;
      const done = PROGRESS_ORDER.indexOf(s) < PROGRESS_ORDER.indexOf(current);
      return `<span class="step ${done ? "done" : ""} ${active ? (failed ? "failed" : "active") : ""}">${s === "CHAIN_VERIFIED" ? "CHAIN VERIFIED" : s}</span>`;
    }).join("<span class=arrow>→</span>")}</div>${failed ? `<div class="fail-state">${esc(failed)}</div>` : ""}`;
  }

  /*
   * Canonical review rows. `book` maps x-only pubkeys back to the wallet
   * addresses the user entered — DISPLAY ONLY: the canonical values stay
   * the consensus pubkeys from the built request (title shows them).
   */
  function reviewHtml(review, book = {}) {
    const fmt = (v) =>
      Array.isArray(v)
        ? v.map((x) => (book[x] ? `<span title="${esc(x)}">${esc(book[x])}</span>` : esc(shortId(x)))).join(", ")
        : book[v]
          ? `<span title="${esc(v)}">${esc(book[v])}</span>`
          : esc(v);
    const rows = Object.entries(review)
      .filter(([k]) => k !== "action")
      .map(([k, v]) => `<div class="rrow"><span class="rk">${esc(k)}</span><span class="rv mono">${fmt(v)}</span></div>`)
      .join("");
    return `<div class="review"><div class="raction">${esc(review.action)}</div>${rows}</div>`;
  }

  function openModal(html) {
    $("modal-body").innerHTML = html;
    $("modal").style.display = "flex";
  }
  function closeModal() {
    $("modal").style.display = "none";
    $("modal-body").innerHTML = "";
  }
  $("modal-close")?.addEventListener?.("click", closeModal);

  function note(message, cls) {
    const el = $("notice");
    el.textContent = message;
    el.className = `notice ${cls || ""}`;
    el.style.display = "block";
    setTimeout(() => (el.style.display = "none"), 8000);
  }

  /*
   * Drive one wallet request: build server-side, show the CANONICAL review
   * (derived from the built request, not the form), request the wallet
   * signature, finalize, and show the durable state machine.
   */
  async function runWalletFlow(buildFn, label, addressBook) {
    if (ui.state !== WalletState.READY) {
      note(`Connect a wallet on ${networkLabel()} first.`, "warn");
      return;
    }
    let request;
    try {
      request = (await buildFn()).request;
    } catch (e) {
      openModal(`<h3>${esc(label)} — BUILD FAILED</h3><div class="fail-state">${esc(e.code || "")} ${esc(e.message)}</div>`);
      return;
    }
    ui.activeRequest = request;

    openModal(`
      <h3>Review ${esc(label)}</h3>
      ${reviewHtml(request.review, addressBook)}
      ${progressHtml("BUILT")}
      <div class="modal-actions">
        <button id="btn-sign" class="primary">Sign with ${esc(ui.adapter.label)}</button>
        <button id="btn-cancel">Cancel</button>
      </div>`);

    $("btn-cancel").onclick = async () => {
      await postJSON(`/wallet/requests/${request.requestId}/reject`, {}).catch(() => {});
      ui.activeRequest = null;
      closeModal();
    };
    $("btn-sign").onclick = async () => {
      // Bind to the exact signer the request was built for.
      if (ui.adapter.getActiveAddress() !== request.signerAddress) {
        note(`Wrong wallet account. Required: ${request.signerAddress}`, "warn");
        return;
      }
      const body = $("modal-body");
      const setProgress = (s, failed) => {
        const p = body.querySelector(".progress")?.parentElement;
        body.querySelector(".progress")?.remove();
        body.querySelector(".fail-state")?.remove();
        body.insertAdjacentHTML("beforeend", progressHtml(s, failed));
        void p;
      };
      try {
        setProgress("AWAITING SIGNATURE");
        const signedSafeJson = await ui.adapter.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
        setProgress("SIGNED");
        setProgress("SUBMITTING");
        const done = await postJSON(`/wallet/requests/${request.requestId}/signature`, { signedSafeJson });
        setProgress(done.request.state, done.request.state === "CHAIN_VERIFIED" ? null : done.request.state);
        if (done.request.state === "CHAIN_VERIFIED") {
          body.insertAdjacentHTML("beforeend", `<div class="ok-state">CHAIN VERIFIED · txid <span class="mono">${esc(done.request.txId)}</span> · fee ${esc(done.request.review.feeKas ?? "")} KAS</div>`);
          ui.activeRequest = null;
          await loadVaults();
        }
      } catch (e) {
        const advanced = `<details class="adv"><summary>Advanced</summary><div class="mono hint">${esc(e.code || "")} ${esc(e.message)}<br>request ${esc(request.requestId)}${e.payload?.request?.txId ? `<br>txid ${esc(e.payload.request.txId)}` : ""}</div></details>`;
        if (e.walletCategory === "USER_REJECTED") {
          await postJSON(`/wallet/requests/${request.requestId}/reject`, {}).catch(() => {});
          setProgress("AWAITING SIGNATURE", "WALLET REJECTED — no transaction was signed or sent");
        } else if (e.code === "SUBMISSION_REJECTED") {
          body.querySelector(".progress")?.remove();
          body.querySelector(".fail-state")?.remove();
          body.insertAdjacentHTML("beforeend", `<div class="fail-state">The network rejected this transaction. Your vault was not changed.</div>${advanced}`);
        } else if (e.code === "RECONCILIATION_REQUIRED") {
          body.querySelector(".progress")?.remove();
          body.querySelector(".fail-state")?.remove();
          body.insertAdjacentHTML("beforeend", `
            <div class="fail-state">Transaction status is uncertain. PolicyVault must verify the vault on-chain before another action can be performed.</div>
            <div class="modal-actions"><button class="primary" onclick="pvActions.verify('${esc(request.vaultId)}'); document.getElementById('modal').style.display='none';">Verify Vault State</button></div>
            ${advanced}`);
        } else if (e.code === "CLAIM_CONFLICT") {
          body.querySelector(".progress")?.remove();
          body.querySelector(".fail-state")?.remove();
          body.insertAdjacentHTML("beforeend", `
            <div class="fail-state">Another transaction for this vault is still being resolved. This operation stays blocked until it is verified.</div>
            <div class="modal-actions"><button class="primary" onclick="pvActions.verify('${esc(request.vaultId)}'); document.getElementById('modal').style.display='none';">Go to verification</button></div>
            ${advanced}`);
        } else {
          const st = e.payload?.request?.state || e.code || "FAILED";
          setProgress(st, `${st}: ${e.message}`);
        }
        ui.activeRequest = null;
        await loadVaults();
      }
    };
  }

  /* ---------------- actions ---------------- */

  function act(vaultId, action, params, label, addressBook) {
    runWalletFlow(() => postJSON("/wallet/requests", { vaultId, action, params, signerAddress: ui.adapter.getActiveAddress() }), label, addressBook);
  }

  function promptSompi(msg) {
    const v = window.prompt(msg);
    if (!v) return null;
    const kasVal = Number(v);
    if (!Number.isFinite(kasVal) || kasVal <= 0) {
      note("Invalid amount", "warn");
      return null;
    }
    return BigInt(Math.round(kasVal * 1e8)).toString();
  }

  window.pvActions = {
    spend(vaultId) {
      const amount = promptSompi("Spend amount (KAS):");
      if (!amount) return;
      const idx = Number(window.prompt("Recipient index (1-3):", "1"));
      if (![1, 2, 3].includes(idx)) return note("Recipient index must be 1..3", "warn");
      act(vaultId, "delegateSpend", { payAmountSompi: amount, recipientIndex: idx }, "Delegate spend");
    },
    pause: (v) => act(v, "ownerPause", {}, "Pause vault"),
    unpause: (v) => act(v, "ownerUnpause", {}, "Unpause vault"),
    revoke: (v) => act(v, "revokeDelegate", {}, "Revoke delegate"),
    async rotate(v) {
      const addr = window.prompt("New delegate wallet address (kaspatest:...):");
      if (!addr) return;
      let id;
      try {
        id = await PolicyVaultIdentity.resolveAddress(API, addr);
      } catch (e) {
        return note(`Delegate wallet address: ${e.message}`, "warn");
      }
      act(v, "rotateDelegate", { newDelegate: id.xOnlyPubkey }, "Rotate delegate", { [id.xOnlyPubkey]: id.address });
    },
    topup(v) {
      const amount = promptSompi("Top-up amount (KAS):");
      if (amount) act(v, "ownerTopUp", { topUpAmountSompi: amount }, "Top up vault");
    },
    migrate(v) {
      const cap = promptSompi("New per-spend cap (KAS, blank = keep):");
      const budget = promptSompi("New period budget (KAS, blank = keep):");
      const newPolicy = {};
      if (cap) newPolicy.maxPerSpend = cap;
      if (budget) newPolicy.periodBudget = budget;
      if (!Object.keys(newPolicy).length) return note("Nothing to change", "warn");
      act(v, "migratePolicy", { newPolicy }, "Migrate policy");
    },
    closeVault(v) {
      // Owner-only terminal recovery via the existing ownerRecover path.
      if (!window.confirm("Close this vault and withdraw the FULL protected value to your owner wallet?\nThis ends the vault permanently.")) return;
      act(v, "ownerRecover", {}, "Close vault & withdraw");
    },
    /*
     * "Verify Vault State": invokes ONLY the existing reconcile path
     * (exact chain proof, default gates). No claim deletion, no force
     * unlock — uncertainty stays fail-closed.
     */
    async verify(v, { quiet } = {}) {
      if (!quiet) note("Verifying vault state on-chain…");
      let reconcile;
      try {
        ({ reconcile } = await postJSON(`/vaults/${v}/reconcile`, {}));
      } catch (e) {
        note(`Verification failed: ${e.message}`, "warn");
        return loadVaults();
      }
      const messages = {
        CONSISTENT: "Vault verified. No transaction occurred.",
        CLAIM_RELEASED: "Vault verified. No transaction occurred — the vault is available again.",
        ADVANCED: "Transaction confirmed on-chain — the vault advanced to the verified successor state.",
        TERMINAL: "This vault is closed.",
        CLAIM_PENDING: "Still verifying — the outcome cannot be proven yet. Try again in a couple of minutes.",
        UNKNOWN: "Automatic verification could not establish the vault state. Controls remain disabled."
      };
      note(messages[reconcile.status] ?? `Verification result: ${reconcile.status}`, reconcile.status === "UNKNOWN" ? "warn" : "");
      return loadVaults();
    },
    async cancelRequest(requestId) {
      await postJSON(`/wallet/requests/${requestId}/reject`, {}).catch(() => {});
      return loadVaults();
    }
  };

  /* ---------------- create vault ---------------- */

  $("create-form")?.addEventListener?.("submit", async (ev) => {
    ev.preventDefault();
    if (ui.state !== WalletState.READY) return note(`Connect a wallet on ${networkLabel()} first.`, "warn");
    const f = new FormData(ev.target);
    const dep = promptCheck(f.get("deposit"), "deposit");
    const cap = promptCheck(f.get("cap"), "per-spend cap");
    const budget = promptCheck(f.get("budget"), "period budget");
    if (!dep || !cap || !budget) return;

    /*
     * Users enter WALLET ADDRESSES; the covenant identities are resolved
     * through the backend's single address boundary BEFORE any transaction
     * request is built. The owner is never typed — it is the connected
     * wallet, cross-checked against the wallet's own public key.
     */
    let ids;
    try {
      ids = await PolicyVaultIdentity.resolveCreateIdentities(API, ui.adapter, {
        delegateAddress: f.get("delegate"),
        recipientAddresses: [f.get("recipient1"), f.get("recipient2"), f.get("recipient3")]
      });
    } catch (e) {
      return note(e.message, "warn");
    }
    const vaultId = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
    renderAdvancedIdentity(ids, vaultId);
    const addressBook = Object.fromEntries(
      [ids.owner, ids.delegate, ...ids.recipients].map((i) => [i.xOnlyPubkey, i.address])
    );

    runWalletFlow(async () => {
      const net = await getJSON("/network/status");
      return postJSON("/wallet/create", {
        signerAddress: ui.adapter.getActiveAddress(),
        label: String(f.get("label") || ""),
        templateInput: { owner: ids.owner.xOnlyPubkey, vaultId },
        initialStateInput: {
          protectedValue: dep,
          periodStartDaa: (BigInt(net.virtualDaaScore) - 10n).toString(),
          periodSpent: "0",
          paused: "0",
          delegate: ids.delegate.xOnlyPubkey,
          maxPerSpend: cap,
          periodBudget: budget,
          periodLengthDaa: String(f.get("periodLength") || "600"),
          recipients: ids.recipients.map((r) => r.xOnlyPubkey),
          delegateActive: "1",
          policyNonce: "0"
        }
      });
    }, "Create vault", addressBook);
  });

  function promptCheck(v, label) {
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) {
      note(`Invalid ${label}`, "warn");
      return null;
    }
    return BigInt(Math.round(n * 1e8)).toString();
  }

  /* ---------------- organizations (OFF-CHAIN metadata only) ---------------- */

  const healthyOrgs = () => ui.orgs.filter((o) => !o.error);
  const orgById = (id) => healthyOrgs().find((o) => o.orgId === id) ?? null;

  /* Member lookup by on-chain identity; prefers the vault's own org. */
  function memberByXOnly(xonly, preferOrgId) {
    if (!xonly) return null;
    const search = (orgs) => {
      for (const o of orgs) {
        const m = (o.members ?? []).find((mm) => mm.xOnlyPubkey === xonly && mm.status === "ACTIVE");
        if (m) return { member: m, org: o };
      }
      return null;
    };
    const preferred = preferOrgId ? healthyOrgs().filter((o) => o.orgId === preferOrgId) : [];
    return search(preferred) ?? search(healthyOrgs());
  }

  async function loadOrgs() {
    try {
      const data = await getJSON("/organizations");
      ui.orgs = data.organizations ?? [];
      ui.roleLabels = data.roleLabels ?? [];
      ui.assignments = data.assignments ?? {};
      ui.assignmentsVersion = data.assignmentsVersion ?? 0;
      ui.assignmentsError = data.assignmentsError ?? null;
      if (ui.assignmentsError) note("Organization assignment metadata is unreadable — vaults are shown as Unassigned. Vault funds are unaffected.", "warn");
      const corrupt = ui.orgs.filter((o) => o.error);
      if (corrupt.length) note(`${corrupt.length} organization record(s) are unreadable (metadata error). Vault funds are unaffected.`, "warn");
    } catch (e) {
      ui.orgs = [];
      note(`Organizations unavailable: ${e.message}`, "warn");
    }
    renderOrgSelector();
    renderOrgPanel();
  }

  function renderOrgSelector() {
    const sel = $("org-selector");
    if (!sel) return;
    const current = ui.selectedOrg;
    sel.innerHTML = `<option value="all">All vaults</option><option value="unassigned">Unassigned vaults</option>` +
      healthyOrgs().map((o) => `<option value="${esc(o.orgId)}">${esc(o.name)}</option>`).join("") +
      ui.orgs.filter((o) => o.error).map((o) => `<option value="${esc(o.orgId)}" disabled>⚠ unreadable organization</option>`).join("");
    sel.value = [...sel.options].some((op) => op.value === current) ? current : "all";
    ui.selectedOrg = sel.value;
    $("btn-org-rename").style.display = orgById(ui.selectedOrg) ? "" : "none";
  }

  function renderOrgPanel() {
    const panel = $("org-panel");
    if (!panel) return;
    const org = orgById(ui.selectedOrg);
    panel.style.display = org ? "" : "none";
    if (!org) return;

    const orgVaults = ui.vaults.filter((v) => v.organization?.orgId === org.orgId);
    const live = orgVaults.filter((v) => v.operational?.status !== "CLOSED");
    const actionRequired = orgVaults.filter((v) => ["ACTION_REQUIRED_VERIFY", "UNKNOWN"].includes(v.operational?.status));
    const closed = orgVaults.filter((v) => v.operational?.status === "CLOSED");
    const activeDelegates = new Set(live.filter((v) => v.live?.delegateActive).map((v) => v.delegate));
    const totalKas = live.reduce((s, v) => s + (Number(v.live?.protectedValueKas) || 0), 0);
    $("org-overview").innerHTML = `
      <div class="grid">
        <div class="field"><div class="k">Active vaults</div><div class="v">${live.length}</div></div>
        <div class="field"><div class="k">Total protected</div><div class="v">${esc(totalKas.toLocaleString())} KAS</div></div>
        <div class="field"><div class="k">Action required</div><div class="v">${actionRequired.length}</div></div>
        <div class="field"><div class="k">Active delegates</div><div class="v">${activeDelegates.size}</div></div>
        <div class="field"><div class="k">Closed vaults</div><div class="v">${closed.length}</div></div>
      </div>
      <div class="org-note">Totals are informational sums across separate on-chain vaults — not a single account. Organization data is application metadata and grants no covenant authority.</div>`;

    // Members: organization role labels vs actual on-chain authority.
    const authorityOf = (m) => {
      if (!m.xOnlyPubkey) return "No signing identity (contact only)";
      const owned = ui.vaults.filter((v) => v.owner === m.xOnlyPubkey && v.operational?.status !== "CLOSED").length;
      const delegateOf = ui.vaults.filter((v) => v.delegate === m.xOnlyPubkey && v.live?.delegateActive && v.operational?.status !== "CLOSED").length;
      const parts = [];
      if (owned) parts.push(`ON-CHAIN OWNER of ${owned} vault${owned > 1 ? "s" : ""}`);
      if (delegateOf) parts.push(`ON-CHAIN ACTIVE DELEGATE of ${delegateOf} vault${delegateOf > 1 ? "s" : ""}`);
      return parts.length ? parts.join(" · ") : "None";
    };
    $("org-members").innerHTML = org.members.length
      ? `<table class="mtable"><tr><th>Member</th><th>Wallet</th><th>Organization role</th><th>On-chain authority</th><th></th></tr>` +
        org.members.map((m) => `<tr>
          <td>${esc(m.displayName)}${m.status === "INACTIVE" ? ' <span class="tag meta">INACTIVE</span>' : ""}</td>
          <td class="mono id">${m.address ? esc(shortId(m.address)) : "—"}</td>
          <td>${m.roles.map((r) => `<span class="tag meta">${esc(r)}</span>`).join("")}${m.roles.includes("approver") ? '<div class="org-note">Organization role only — on-chain approvals arrive in v0.3</div>' : ""}</td>
          <td>${esc(authorityOf(m))}</td>
          <td>
            <button class="copy" onclick="pvOrg.memberRoles('${esc(m.memberId)}')">roles</button>
            <button class="copy" onclick="pvOrg.memberToggle('${esc(m.memberId)}')">${m.status === "ACTIVE" ? "deactivate" : "activate"}</button>
            <button class="copy" onclick="pvOrg.memberRemove('${esc(m.memberId)}')">remove</button>
          </td></tr>`).join("") + `</table>`
      : `<div class="empty">No members yet.</div>`;

    // Roles checkboxes for the add-member form.
    $("member-roles").innerHTML = ui.roleLabels
      .map((r) => `<label class="tag"><input type="checkbox" name="role" value="${esc(r)}"> ${esc(r)}</label>`)
      .join(" ");

    // Delegate visibility (navigation only — mutations stay on the vault card).
    const delRows = live.filter((v) => v.live).map((v) => {
      const match = memberByXOnly(v.delegate, org.orgId);
      return `<tr>
        <td class="mono id">${esc(shortId(v.delegateAddress || v.delegate))}</td>
        <td>${v.live.delegateActive ? "ACTIVE" : "REVOKED"}${v.live.paused ? " · vault PAUSED" : ""}</td>
        <td>${esc(v.label || shortId(v.vaultId))}</td>
        <td>${esc(v.policy?.maxPerSpendKas ?? "—")} KAS</td>
        <td>${esc(v.live.remainingBudgetKas ?? "—")} / ${esc(v.policy?.periodBudgetKas ?? "—")} KAS</td>
        <td>${match ? esc(match.member.displayName) : '<span class="org-note">no member record</span>'}</td>
        <td><button class="copy" onclick="document.getElementById('vault-${esc(v.vaultId)}')?.scrollIntoView({behavior:'smooth'})">go to vault</button></td>
      </tr>`;
    });
    $("org-delegates").innerHTML = delRows.length
      ? `<table class="mtable"><tr><th>Delegate wallet</th><th>Status</th><th>Vault</th><th>Per-spend cap</th><th>Remaining / budget</th><th>Member</th><th></th></tr>${delRows.join("")}</table>
         <div class="org-note">Rotate/revoke run from the vault card through the standard owner transaction path — this view is navigation only.</div>`
      : `<div class="empty">No live vaults with delegates in this organization.</div>`;

    // Audit: chain events for assigned vaults + this org's metadata events.
    getJSON(`/organizations/${org.orgId}/audit`).then(({ events }) => {
      $("org-audit").innerHTML = events.length
        ? events.map((e) => `<div class="evt">
            <span class="tag ${e.eventType === "CHAIN EVENT" ? "chain" : "meta"}">${e.eventType === "CHAIN EVENT" ? "CHAIN EVENT" : "METADATA"}</span>
            <span class="mono">${esc(e.at ?? "")}</span> ${esc(e.action ?? "")}
            ${e.vaultId ? `· vault <span class="mono id">${esc(shortId(e.vaultId))}</span>` : ""}
            ${e.txId ? `· tx <span class="mono id">${esc(shortId(e.txId))}</span>` : ""}
            ${e.detail ? `· ${esc(e.detail)}` : ""}
            ${e.result ? `· ${esc(e.result)}` : ""}
          </div>`).join("")
        : `<div class="empty">No events yet.</div>`;
    }).catch((e) => {
      $("org-audit").innerHTML = `<div class="empty">Audit unavailable: ${esc(e.message)}</div>`;
    });
  }

  window.pvOrg = {
    async create() {
      const name = window.prompt("Organization name:");
      if (!name) return;
      try {
        const { organization } = await postJSON("/organizations", { name });
        ui.selectedOrg = organization.orgId;
        localStorage.setItem("pv.selectedOrg", ui.selectedOrg);
        await loadOrgs();
        note(`Organization "${organization.name}" created.`);
      } catch (e) {
        note(e.message, "warn");
      }
    },
    async rename() {
      const org = orgById(ui.selectedOrg);
      if (!org) return;
      const name = window.prompt("New organization name:", org.name);
      if (!name || name === org.name) return;
      try {
        await postJSON(`/organizations/${org.orgId}/rename`, { name, expectedVersion: org.version });
        await loadOrgs();
        note("Organization renamed (metadata only — nothing on-chain changed).");
      } catch (e) {
        note(e.message, "warn");
      }
    },
    async memberRoles(memberId) {
      const org = orgById(ui.selectedOrg);
      const m = org?.members.find((x) => x.memberId === memberId);
      if (!m) return;
      const roles = window.prompt(`Roles (comma separated: ${ui.roleLabels.join(", ")}):`, m.roles.join(", "));
      if (roles == null) return;
      try {
        await postJSON(`/organizations/${org.orgId}/members/${memberId}`, { roles: roles.split(",").map((s) => s.trim()).filter(Boolean), expectedVersion: org.version });
        await loadOrgs();
      } catch (e) {
        note(e.message, "warn");
      }
    },
    async memberToggle(memberId) {
      const org = orgById(ui.selectedOrg);
      const m = org?.members.find((x) => x.memberId === memberId);
      if (!m) return;
      try {
        await postJSON(`/organizations/${org.orgId}/members/${memberId}`, { status: m.status === "ACTIVE" ? "INACTIVE" : "ACTIVE", expectedVersion: org.version });
        await loadOrgs();
      } catch (e) {
        note(e.message, "warn");
      }
    },
    async memberRemove(memberId) {
      const org = orgById(ui.selectedOrg);
      if (!org || !window.confirm("Remove this member record? (Metadata only — no on-chain effect.)")) return;
      try {
        await postJSON(`/organizations/${org.orgId}/members/${memberId}/remove`, { expectedVersion: org.version });
        await loadOrgs();
      } catch (e) {
        note(e.message, "warn");
      }
    },
    async assign(vaultId, orgId) {
      try {
        if (orgId === "unassigned") {
          await postJSON(`/organizations/${ui.assignments[vaultId]?.orgId}/vaults/${vaultId}/unassign`, { expectedVersion: ui.assignmentsVersion });
        } else {
          const group = window.prompt("Group label (optional, e.g. Payroll / Vendors / Operations):", ui.assignments[vaultId]?.group ?? "") || null;
          await postJSON(`/organizations/${orgId}/vaults`, { vaultId, group, expectedVersion: ui.assignmentsVersion });
        }
        await Promise.all([loadOrgs(), loadVaults()]);
      } catch (e) {
        note(e.message, "warn");
        await loadOrgs();
      }
    }
  };

  /* ---------------- vault rendering (version-aware) ---------------- */

  /* Compact operational labels (raw internal terms never lead the UX). */
  const OP_LABEL = {
    ACTIVE: null,
    WAITING_FOR_SIGNATURE: "WAITING FOR SIGNATURE",
    TRANSACTION_PENDING: "TRANSACTION PENDING",
    ACTION_REQUIRED_VERIFY: "ACTION REQUIRED — VERIFY VAULT",
    CLOSED: "CLOSED",
    UNKNOWN: "UNVERIFIED"
  };

  /* Advanced diagnostics (public identifiers only — never key material). */
  function advancedDetailsHtml(op) {
    const rows = [];
    const add = (k, v) => v !== null && v !== undefined && rows.push(`${k}: ${v}`);
    if (op.request) {
      add("request", op.request.requestId);
      add("request state", op.request.state);
      add("action", op.request.action);
      add("txid", op.request.txId);
      if (op.request.predecessorOutpoint) add("predecessor", `${op.request.predecessorOutpoint.transactionId}:${op.request.predecessorOutpoint.index}`);
      add("expected successor state", op.request.successorStateId);
      add("created", op.request.createdAt);
      add("detail", op.request.error);
    }
    if (op.claim) {
      add("claimed action", op.claim.action);
      add("claimed txid", op.claim.txId);
      if (op.claim.outpoint) add("claimed outpoint", `${op.claim.outpoint.transactionId}:${op.claim.outpoint.index}`);
      add("claim created", op.claim.createdAt);
      add("expected effect", op.claim.expectedKind);
    }
    add("reason", op.reason);
    if (!rows.length) return "";
    return `<details class="adv"><summary>Advanced</summary><div class="mono hint">${rows.map(esc).join("<br>")}</div></details>`;
  }

  /* Operational banner: plain language, no raw exception as primary UX. */
  function operationalHtml(v) {
    const op = v.operational;
    if (!op || op.status === "ACTIVE" || op.status === "CLOSED") return "";
    if (op.status === "WAITING_FOR_SIGNATURE") {
      return `<div class="opbanner">Waiting for wallet approval.
        ${op.request ? `<button class="act" onclick="pvActions.cancelRequest('${esc(op.request.requestId)}')">Cancel request</button>` : ""}
        ${advancedDetailsHtml(op)}</div>`;
    }
    if (op.status === "TRANSACTION_PENDING") {
      return `<div class="opbanner">Transaction pending — waiting for chain confirmation. This is not yet success.
        <button class="act" onclick="pvActions.verify('${v.vaultId}')">Verify vault state</button>
        ${advancedDetailsHtml(op)}</div>`;
    }
    if (op.status === "ACTION_REQUIRED_VERIFY") {
      return `<div class="opbanner warn">Transaction status is uncertain. PolicyVault must verify the vault on-chain before another action can be performed.
        <button class="act primary" onclick="pvActions.verify('${v.vaultId}')">Verify Vault State</button>
        ${advancedDetailsHtml(op)}</div>`;
    }
    if (op.status === "UNKNOWN") {
      return `<div class="opbanner bad">Automatic verification could not establish this vault's state. Controls are disabled (fail closed) — resolve by inspection of the identifiers below.
        ${advancedDetailsHtml(op)}</div>`;
    }
    return "";
  }

  function actionButtons(v) {
    if (v.contractVersion === "policyvault-0.1-beta") {
      return `<div class="upgrade-note">v0.1 vault — in-lineage migration to v0.2 is not possible (proven).
        Supported upgrade: OWNER RECOVER this vault, then CREATE a new v0.2 vault.</div>`;
    }
    if (v.contractVersion !== "policyvault-0.2") {
      return `<div class="fail-state">UNSUPPORTED VERSION ${esc(v.contractVersion)} — controls disabled (fail closed)</div>`;
    }
    if (!v.live) return "";
    /*
     * Mutation controls exist ONLY while the vault is operationally
     * ACTIVE: any pending signature/submission, unresolved claim, or
     * fail-closed state hides them (the banner explains why). There is
     * no force-unlock or claim-deletion control anywhere.
     */
    if (v.operational && v.operational.status !== "ACTIVE") return "";
    if (ui.state !== WalletState.READY) {
      return `<div class="hint">Connect a wallet to enable actions.</div>`;
    }
    /*
     * ROLE-AWARE controls: show only actions the connected wallet can
     * actually authorize. UI filtering is convenience — the backend
     * enforces signer authorization independently on every request.
     */
    const isOwner = !!ui.walletXOnly && ui.walletXOnly === v.owner;
    const isDelegate = !!ui.walletXOnly && ui.walletXOnly === v.delegate;
    if (!isOwner && !isDelegate) {
      return `<div class="hint">Connected wallet has no role in this vault — read-only.</div>`;
    }
    const b = (fn, label, cls) => `<button class="act ${cls || ""}" onclick="pvActions.${fn}('${v.vaultId}')">${label}</button>`;
    const paused = v.live.paused;
    const buttons = [];
    if (isDelegate && v.live.delegateActive !== false && !paused) buttons.push(b("spend", "Spend"));
    if (isOwner) {
      buttons.push(paused ? b("unpause", "Unpause") : b("pause", "Pause"));
      if (v.live.delegateActive !== false) buttons.push(b("revoke", "Revoke delegate", "warn"));
      buttons.push(b("rotate", "Rotate delegate"), b("topup", "Top up"), b("migrate", "Migrate policy"));
      buttons.push(b("closeVault", "Close vault & withdraw", "warn"));
    }
    const roles = [isOwner ? "OWNER" : null, isDelegate ? "DELEGATE" : null].filter(Boolean).join(" + ");
    return `<div class="actions">${buttons.join("")}</div>
    <div class="hint">Connected as ${roles} of this vault.${isDelegate && !isOwner && (paused || v.live.delegateActive === false) ? " Spending is currently unavailable (vault paused or delegate revoked)." : ""}</div>`;
  }

  /*
   * Identity display: wallet address (never raw pubkeys in normal UX) +
   * organization member name if one matches + the ACTUAL on-chain
   * authority tag. Organization names never replace the authority tag.
   */
  function identityHtml(v, xonly, address, authorityTag) {
    const match = memberByXOnly(xonly, v.organization?.orgId);
    const who = address ? shortId(address) : shortId(xonly);
    return `${match ? `${esc(match.member.displayName)} — ` : ""}<span class="mono id" title="${esc(xonly ?? "")}">${esc(who)}</span> <span class="tag chain">${esc(authorityTag)}</span>`;
  }

  /* Off-chain assignment control (metadata only; never touches the chain). */
  function orgAssignHtml(v) {
    const options = [`<option value="unassigned" ${!v.organization ? "selected" : ""}>Unassigned</option>`]
      .concat(healthyOrgs().map((o) => `<option value="${esc(o.orgId)}" ${v.organization?.orgId === o.orgId ? "selected" : ""}>${esc(o.name)}</option>`));
    return `<div class="org-assign">
      <span>Organization:</span>
      <select onchange="pvOrg.assign('${esc(v.vaultId)}', this.value)">${options.join("")}</select>
      ${v.organization?.group ? `<span class="tag meta">${esc(v.organization.group)}</span>` : ""}
      ${v.organization?.metadataError ? `<span class="tag meta">⚠ metadata unreadable</span>` : ""}
      <span class="org-note">Organization assignment is local PolicyVault metadata and does not change on-chain ownership or permissions.</span>
    </div>`;
  }

  function vaultCard(v) {
    const live = v.live;
    const enforced = live
      ? [
          ["Protected", kas(live.protectedValueKas) + " KAS"],
          ["Per-spend cap", kas(v.policy?.maxPerSpendKas) + " KAS"],
          ["Period budget", kas(v.policy?.periodBudgetKas) + " KAS"],
          ["Spent this period", kas(live.periodSpentKas) + " KAS"],
          ["Remaining", kas(live.remainingBudgetKas) + " KAS"],
          ["Period length", (v.policy?.periodLengthDaa ?? "—") + " DAA"],
          ["Owner", identityHtml(v, v.owner, v.ownerAddress, "ON-CHAIN OWNER")],
          ["Delegate", identityHtml(v, v.delegate, v.delegateAddress, live.delegateActive === false ? "REVOKED ON-CHAIN" : "ON-CHAIN ACTIVE DELEGATE")],
          ["Policy nonce", live.policyNonce ?? "—"],
          ["Covenant id", `<span class="mono id">${shortId(live.covenantId)}</span>`]
        ]
      : [];
    return `
      <div class="vault" id="vault-${esc(v.vaultId)}">
        <div class="vault-head">
          <div>
            <div class="vault-title">${esc(v.label || "Unnamed vault")}
              <span class="badge ${esc(v.status)}">${esc(v.status)}</span>
              <span class="badge ver">${esc(v.contractVersion)}</span>
              ${v.operational && OP_LABEL[v.operational.status] ? `<span class="badge op-${esc(v.operational.status)}">${esc(OP_LABEL[v.operational.status])}</span>` : ""}
            </div>
            <div class="mono id" title="off-chain label; ids are consensus values">${esc(v.vaultId)}</div>
          </div>
          ${live?.paused ? '<span class="badge PAUSED">PAUSED</span>' : ""}
        </div>
        <div class="onchain-tag">ON-CHAIN ENFORCED</div>
        <div class="grid">${enforced.map(([k, val]) => `<div class="field"><div class="k">${k}</div><div class="v">${val}</div></div>`).join("")}</div>
        ${live ? `<div class="field" style="margin-top:0.8rem"><div class="k">Live outpoint</div><div class="v mono id">${esc(live.outpoint.transactionId)}:${live.outpoint.index}
          <button class="copy" onclick="navigator.clipboard.writeText('${esc(live.outpoint.transactionId)}')">copy</button></div></div>` : ""}
        ${v.operational?.status === "CLOSED" ? `<div class="hint">This vault is closed — the protected value was returned to the owner. It remains available for organization history and audit.</div>` : ""}
        ${operationalHtml(v)}
        ${actionButtons(v)}
        ${orgAssignHtml(v)}
      </div>`;
  }

  function renderVaults() {
    const el = $("vaults");
    if (!el) return;
    let vaults = ui.vaults;
    if (ui.selectedOrg === "unassigned") vaults = vaults.filter((v) => !v.organization);
    else if (ui.selectedOrg !== "all") vaults = vaults.filter((v) => v.organization?.orgId === ui.selectedOrg);
    if (!vaults.length) {
      el.innerHTML = `<div class="empty">${ui.vaults.length ? "No vaults in this view." : "No vaults yet — create one above."}</div>`;
      return;
    }
    if (orgById(ui.selectedOrg)) {
      // Organization view: coherent grouping by operational bucket.
      const bucketOf = (v) =>
        ["ACTION_REQUIRED_VERIFY", "UNKNOWN"].includes(v.operational?.status) ? "Action required"
        : v.operational?.status === "CLOSED" ? "Closed vaults"
        : "Active vaults";
      const order = ["Action required", "Active vaults", "Closed vaults"];
      el.innerHTML = order
        .map((bucket) => {
          const list = vaults.filter((v) => bucketOf(v) === bucket);
          return list.length ? `<div class="group-head">${bucket}</div>` + list.map(vaultCard).join("") : "";
        })
        .join("");
    } else {
      el.innerHTML = vaults.map(vaultCard).join("");
    }
  }

  /* One automatic verification attempt per vault per page load — the
   * exact proof rules are reconcile-v2's; anything unprovable stays
   * fail-closed with the explicit Verify action offered. */
  const autoVerified = new Set();

  async function loadVaults() {
    try {
      const { vaults } = await getJSON("/vaults");
      ui.vaults = vaults.filter(Boolean);
      renderVaults();
      renderOrgPanel(); // overview/delegate stats derive from vault truth
      for (const v of ui.vaults) {
        if (v.operational?.status === "ACTION_REQUIRED_VERIFY" && !autoVerified.has(v.vaultId)) {
          autoVerified.add(v.vaultId);
          window.pvActions.verify(v.vaultId, { quiet: true });
        }
      }
    } catch (e) {
      $("vaults").innerHTML = `<div class="empty">Failed to load vaults: ${esc(e.message)}</div>`;
    }
  }

  /* ---------------- network identity banner ---------------- */

  /*
   * The top banner reports the network identity of the LIVE backend —
   * GET /network/status, whose networkId is the NODE's own reported
   * network, verified server-side (sdk/src/chain.js connectVerified:
   * node network == configured network, synced, utxoindex). That is the
   * SAME server-reported identity verifyNetwork() gates signing on
   * (ui.serverNetwork), so the banner can never disagree with the
   * transaction safety path. It never assumes a network: the initial
   * markup is a neutral VERIFYING state, and a failed / malformed /
   * still-pending probe shows NETWORK STATUS UNKNOWN (fail closed) —
   * never a stale or guessed network name. A hosted staging deployment's
   * NON-PRODUCTION label (set from /health in boot() below) owns the
   * element outright; network resolution never overwrites it.
   */
  function applyNetworkBanner(networkId) {
    const b = $("testnet-banner");
    if (!b || b.dataset.staging) return; // staging label owns the banner
    if (networkId === "mainnet") {
      b.dataset.net = "mainnet";
      b.textContent = "MAINNET — real KAS";
    } else if (typeof networkId === "string" && networkId) {
      b.dataset.net = "testnet";
      b.textContent = `${networkId.toUpperCase()} — no real value · mainnet broadcasting is disabled`;
    } else {
      b.dataset.net = "unknown";
      b.textContent = "NETWORK STATUS UNKNOWN — verify connection before transacting";
    }
    b.style.display = "";
  }

  let netProbeSeq = 0; // stale-response guard: only the newest probe may write
  let netRetryDelay = 15000; // bounded backoff after failure: 15s → 30s → 60s cap
  async function refreshNetworkStatus() {
    const seq = ++netProbeSeq;
    try {
      const net = await getJSON("/network/status");
      if (seq !== netProbeSeq) return; // a newer probe owns the display
      const id = typeof net.networkId === "string" && net.networkId ? net.networkId : null;
      // verifyNetwork() fails closed unless this is exactly one of the two
      // canonical values — identical gate input to the previous behavior
      // (null here is as unverifiable as the never-assigned initial null).
      ui.serverNetwork = id;
      if (id) {
        $("net").innerHTML = `<span class="ok">●</span> ${esc(id)} · ${net.isSynced ? "synced" : "SYNCING"} · DAA ${esc(net.virtualDaaScore)}`;
        applyNetworkBanner(id);
      } else {
        // Malformed response (no usable networkId): fail closed, keep probing.
        $("net").textContent = "network unknown";
        applyNetworkBanner(null);
        scheduleNetworkRetry();
      }
    } catch {
      if (seq !== netProbeSeq) return;
      ui.serverNetwork = null;
      $("net").textContent = "node unreachable";
      applyNetworkBanner(null);
      scheduleNetworkRetry();
    }
  }
  function scheduleNetworkRetry() {
    // Self-heals a transient node outage: open pages converge to the true
    // network within one retry interval of the backend recovering. Retries
    // stop at the first successful resolution.
    setTimeout(refreshNetworkStatus, netRetryDelay);
    netRetryDelay = Math.min(netRetryDelay * 2, 60000);
  }

  // BROWSER test layer only (web/test/network-banner.test.js): drives and
  // inspects network-banner resolution against the REAL app.js. Production
  // code never uses this.
  window.PolicyVaultNetworkBanner = {
    refresh: refreshNetworkStatus,
    _apply: applyNetworkBanner,
    _serverNetwork: () => ui.serverNetwork
  };

  /* ---------------- boot ---------------- */

  async function boot() {
    // Staging identity (Phase E): a hosted staging deployment reports
    // staging:true from /health; the banner must say NON-PRODUCTION even
    // when the node is unreachable. Server-declared, never inferred.
    getJSON("/health").then((h) => {
      if (h && h.staging) {
        const b = $("testnet-banner");
        // /health always reports networkId (server/src/api.js) — never a
        // hardcoded fallback network name here; an unreadable value fails
        // closed to a neutral label rather than assuming testnet-10.
        const net = typeof h.networkId === "string" && h.networkId ? h.networkId.toUpperCase() : "UNKNOWN NETWORK";
        b.dataset.staging = "1"; // owns the banner — network resolution never overwrites NON-PRODUCTION
        b.textContent = `${net} STAGING — NON-PRODUCTION · no real value · this is not the production site`;
        b.style.display = "";
      }
    }).catch(() => {});
    await refreshNetworkStatus();

    // Provider roster: KasWare always listed; Mock only if the dev endpoint responds.
    // KasWare goes through the Universal-Signer-Interface session adapter
    // (see makeKasWareAdapter above); the connect/reconnect/event surface is
    // unchanged for every consumer.
    const kasware = makeKasWareAdapter();
    $("btn-connect-kasware").onclick = () => connectWith(kasware);
    $("btn-connect-kasware").disabled = false;
    fetch(API + "/wallet/dev-accounts").then((r) => {
      if (r.ok) {
        $("btn-connect-mock").style.display = "";
        $("btn-connect-mock").onclick = () => connectWith(new MockAdapter({ apiBase: API }));
      }
    }).catch(() => {});
    $("btn-disconnect").onclick = disconnect;

    // Reload restore (convenience only; backend remains the source of truth).
    const preferred = localStorage.getItem("pv.walletProvider");
    if (preferred === "kasware" && kasware.detect()) {
      const restored = await kasware.reconnect().catch(() => null);
      if (restored) {
        ui.adapter = kasware;
        ui.address = restored.address;
        await verifyNetwork();
      }
    }
    if (!ui.address) setWalletState(kasware.detect() ? WalletState.DISCONNECTED : WalletState.NOT_DETECTED);

    await initHostedAuth();
    await loadOrgs();
    await loadVaults();
  }

  /* ---------------- organization UI wiring ---------------- */

  $("org-selector")?.addEventListener?.("change", (ev) => {
    ui.selectedOrg = ev.target.value;
    localStorage.setItem("pv.selectedOrg", ui.selectedOrg); // UI convenience only
    renderOrgSelector();
    renderOrgPanel();
    renderVaults();
  });
  $("btn-org-create")?.addEventListener?.("click", () => window.pvOrg.create());
  $("btn-org-rename")?.addEventListener?.("click", () => window.pvOrg.rename());
  $("member-form")?.addEventListener?.("submit", async (ev) => {
    ev.preventDefault();
    const org = orgById(ui.selectedOrg);
    if (!org) return;
    const f = new FormData(ev.target);
    const roles = [...ev.target.querySelectorAll('input[name="role"]:checked')].map((c) => c.value);
    try {
      await postJSON(`/organizations/${org.orgId}/members`, {
        displayName: String(f.get("displayName") || ""),
        address: String(f.get("address") || "").trim() || undefined,
        roles,
        note: String(f.get("note") || "").trim() || undefined,
        expectedVersion: org.version
      });
      ev.target.reset();
      await loadOrgs();
      renderVaults(); // member annotations on cards may change
    } catch (e) {
      note(e.message, "warn");
    }
  });

  $("refresh")?.addEventListener?.("click", () => Promise.all([loadOrgs(), loadVaults()]));
  boot();
})();
