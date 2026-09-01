"use strict";

/*
 * PolicyVault mobile — APP SHELL (platform layer).
 *
 * Plain JavaScript, no framework, no build step — the same style as the
 * existing web client (web/app-v4.js). Screens: Vaults, Agents,
 * Approvals, Activity, Alerts, Verify, Sign (QR/air-gap), Signers,
 * Settings (incl. Build integrity).
 *
 * WHAT THIS FILE IS ALLOWED TO DO: fetch through the vendored API client,
 * arrange DOM, route between screens, and hand documents to the portable
 * layer. WHAT IT IS NOT ALLOWED TO DO: decide anything about a
 * transaction. Every verdict on this screen comes from the packaged
 * verifier; every signing document comes from the portable air-gap
 * module; every capability claim comes from the platform's honest report
 * run through the portable roster.
 *
 * FAIL-CLOSED UX CONTRACT: a screen that cannot do its job says so, with
 * the reason, and offers no control. There are no fake affordances, no
 * empty lists standing in for errors, and no disabled buttons that imply
 * a path exists.
 */

(function () {
  var UI = window.PolicyVaultMobileUi;
  var PLATFORM = window.PolicyVaultMobilePlatform;
  var VERIFICATION = window.PolicyVaultMobileVerification;
  var AIRGAP = window.PolicyVaultMobileAirgap;
  var QR = window.PolicyVaultMobileQrFrames;
  var CAPS = window.PolicyVaultMobileSignerCapabilities;
  var APIMOD = window.PolicyVaultMobileApi;
  var INTEGRITY = window.PolicyVaultMobileBuildIntegrity;

  var el = UI.el;
  var full = UI.full;
  var kv = UI.kv;
  var note = UI.note;
  var unavailable = UI.unavailable;

  var SETTINGS_KEY = "policyvault.mobile.settings.v1";

  /* ------------------------------------------------------------------ */
  /* State                                                               */
  /* ------------------------------------------------------------------ */

  var state = {
    screen: "vaults",
    settings: loadSettings(),
    platform: PLATFORM.report(),
    verification: null,
    api: null,
    roster: null,
    pins: null,
    /* Agents screen: which vault's registry is currently shown. */
    selectedAgentVaultId: null,
    /* the last verification outcome and the payload it is bound to */
    lastVerify: null,
    lastVerifyPayload: null,
    /* air-gap session */
    airgapDoc: null,
    airgapFrames: null,
    airgapFrameIndex: 0,
    airgapTimer: null,
    /* QR-login bootstrap v1 (mobile/docs/session-bootstrap-DESIGN.md §3).
     * walletSessionToken is DELIBERATELY separate from `settings` and is
     * NEVER read from or written to localStorage (§6: memory-only on-phone
     * token handling — it exists only for this run of the app). The other
     * fields here are just this run's in-progress sign-in UI state. */
    walletSessionToken: null,
    authWalletAddressInput: "",
    authChallenge: null,
    authMessageSha256: null
  };

  function loadSettings() {
    var defaults = { baseUrl: "", token: "", network: "testnet-10" };
    try {
      var raw = window.localStorage.getItem(SETTINGS_KEY);
      if (!raw) return defaults;
      var parsed = JSON.parse(raw);
      return {
        baseUrl: typeof parsed.baseUrl === "string" ? parsed.baseUrl : "",
        token: typeof parsed.token === "string" ? parsed.token : "",
        network: parsed.network === "mainnet" ? "mainnet" : "testnet-10"
      };
    } catch (e) {
      return defaults;
    }
  }

  function saveSettings() {
    try { window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(state.settings)); } catch (e) { /* storage is a convenience, never a requirement */ }
  }

  function sha256Hex(text) {
    var core = window.PolicyVaultCore;
    if (!core || typeof core.require !== "function") throw new Error("the packaged core bundle is not loaded");
    return core.require("crypto").createHash("sha256").update(text, "utf8").digest("hex");
  }

  function rebuildServices() {
    state.verification = VERIFICATION.createMobileVerification({
      core: window.PolicyVaultCore,
      verifyIntent: window.PolicyVaultVerifyIntent,
      airgap: AIRGAP
    });
    state.api = APIMOD.createMobileApi({
      httpClient: window.PolicyVaultHttpClient,
      baseUrl: state.settings.baseUrl,
      /* A real wallet session (QR login) takes priority over the
       * Settings-page machine credential when both exist — it is the
       * higher-privilege, user-intended credential once established.
       * Either way this is one bearer token per client instance (the
       * vendored client's credential is immutable after construction),
       * so establishing/clearing a wallet session always goes through
       * rebuildServices() again. */
      token: state.walletSessionToken || state.settings.token || undefined,
      fetchImpl: PLATFORM.fetchImpl()
    });
    state.roster = CAPS.buildSignerRoster({ platform: state.platform });
  }

  /* ------------------------------------------------------------------ */
  /* Screens                                                             */
  /* ------------------------------------------------------------------ */

  var SCREENS = [
    { id: "vaults", label: "Vaults" },
    { id: "agents", label: "Agents" },
    { id: "approvals", label: "Approvals" },
    { id: "activity", label: "Activity" },
    { id: "alerts", label: "Alerts" },
    { id: "verify", label: "Verify" },
    { id: "sign", label: "Sign" },
    { id: "signers", label: "Signers" },
    { id: "settings", label: "Settings" }
  ];

  function panel(title, children) {
    return el("section", { class: "panel" }, [el("h2", { text: title })].concat(children || []));
  }

  /* Every control-plane screen shares this preflight: without a configured
   * server, or without a session, the screen states the reason instead of
   * rendering an empty list. */
  function apiPreflight() {
    if (!state.api.configured) {
      return unavailable("PolicyVault server", state.api.unconfiguredReason + " — open Settings.");
    }
    return null;
  }

  function sessionCard() {
    var b = state.api.sessionBootstrap;
    var box = el("div", { class: "card" }, [
      el("div", { class: "card-head", text: "Session: " + b.status }),
      note(b.reason, "hard")
    ]);
    b.candidates.forEach(function (c) {
      box.appendChild(el("div", { class: "sub" }, [
        el("div", { class: "sub-head", text: c.label + (c.recommended ? "  (recommended in the architecture decision)" : "") }),
        note(c.note)
      ]));
    });
    box.appendChild(note(
      "Until this is decided and built, authenticated reads answer with the server's own refusal, shown verbatim below. A machine credential can be pasted in Settings for read-only testing.",
      ""
    ));
    return box;
  }

  /* --- generic list screen driven by a client call ------------------- */

  function remoteScreen(title, describe, call, renderRows) {
    var host = el("div");
    var pre = apiPreflight();
    if (pre) {
      host.appendChild(panel(title, [note(describe), pre]));
      return host;
    }
    var body = el("div", { class: "card" }, [note("Loading…")]);
    host.appendChild(panel(title, [note(describe), sessionCard(), body]));

    Promise.resolve()
      .then(function () { return call(state.api.client); })
      .then(function (data) {
        body.textContent = "";
        var rows = renderRows(data);
        if (!rows.length) {
          body.appendChild(note("The server returned no entries for this view."));
          return;
        }
        rows.forEach(function (r) { body.appendChild(r); });
      })
      .catch(function (e) {
        var d = state.api.describeError(e);
        body.textContent = "";
        body.appendChild(el("div", { class: "servererr" }, [
          el("div", { class: "servererr-head", text: d.kind + " — " + d.code }),
          full(d.text, "servererr-body")
        ]));
        if (d.kind === "TRANSPORT_FAILURE") body.appendChild(note(d.retryNote, "hard"));
      });

    return host;
  }

  function vaultRow(v) {
    return el("div", { class: "row" }, [
      kv("Vault", v.vaultId || "(unnamed)"),
      kv("Covenant version", v.covenantVersion || v.version || "unknown — shown as unknown, never defaulted"),
      kv("Status", v.status || "unknown"),
      kv("Protected value (sompi)", v.protectedValue !== undefined ? String(v.protectedValue) : "unknown"),
      kv("Fee reserve (sompi)", v.feeReserve !== undefined ? String(v.feeReserve) : "unknown")
    ]);
  }

  function screenVaults() {
    return remoteScreen(
      "Vaults",
      "Read/coordinate only. Balances, protected value, fee reserve, live outpoint and covenant version come from the hosted API; an unknown covenant version is displayed as unknown and never routed to a default.",
      function (c) { return c.listVaults(); },
      function (data) {
        var list = Array.isArray(data) ? data : (data && Array.isArray(data.vaults) ? data.vaults : []);
        return list.map(vaultRow);
      }
    );
  }

  /* --- Agents: vault selection + read-only agent-registry listing ---
   *
   * Agent policy is nested inside a vault's detail document (§ same
   * remote-data discipline as Vaults/Approvals/Activity): read-only,
   * server-refusal vs transport-failure never conflated, no fake
   * affordances. There is NO mutation here — no suspend, rotate, or
   * policy-change control — this screen only lists what the server
   * already reports for a vault the caller can already read.
   *
   * A v0.4 vault's presented document carries `agents: [...]` (the
   * durable, root-verified registry: server/src/api.js presentVaultV4).
   * A v0.2/v0.3 vault carries a single `delegate` instead — multiple
   * independent agents are a v0.4 covenant feature, so an older vault is
   * reported as such rather than shown as "no agents" (which would look
   * like an empty, and wrong, registry).
   */
  function screenAgents() {
    var host = el("div");
    var pre = apiPreflight();
    if (pre) {
      host.appendChild(panel("Agents", [
        note("Per-agent policy, per-spend caps, period budgets and recipient allowlists are read from each vault's detail document."),
        pre
      ]));
      return host;
    }

    var selectBody = el("div", { class: "card" }, [note("Loading vaults…")]);
    var detailBody = el("div");

    host.appendChild(panel("Agents", [
      note("Per-agent policy, per-spend caps, period budgets and recipient allowlists are read from each vault's detail document. Select a vault to load its agent registry. Read-only — no suspend, rotate, or policy-change action is offered from this screen."),
      sessionCard(),
      selectBody,
      detailBody
    ]));

    Promise.resolve()
      .then(function () { return state.api.client.listVaults(); })
      .then(function (data) {
        var list = Array.isArray(data) ? data : (data && Array.isArray(data.vaults) ? data.vaults : []);
        selectBody.textContent = "";
        if (!list.length) {
          selectBody.appendChild(note("The server returned no vaults for this account."));
          return;
        }
        list.forEach(function (v) {
          var vaultId = v.vaultId;
          var selected = state.selectedAgentVaultId === vaultId;
          selectBody.appendChild(el("div", { class: "row" }, [
            kv("Vault", vaultId || "(unnamed)"),
            kv("Contract version", v.contractVersion || "unknown — shown as unknown, never defaulted"),
            el("button", {
              class: "btn" + (selected ? " primary" : ""),
              text: selected ? "Selected" : "Select",
              onclick: function () { state.selectedAgentVaultId = vaultId; go("agents"); }
            })
          ]));
        });
      })
      .catch(function (e) {
        var d = state.api.describeError(e);
        selectBody.textContent = "";
        selectBody.appendChild(el("div", { class: "servererr" }, [
          el("div", { class: "servererr-head", text: d.kind + " — " + d.code }),
          full(d.text, "servererr-body")
        ]));
        if (d.kind === "TRANSPORT_FAILURE") selectBody.appendChild(note(d.retryNote, "hard"));
      });

    if (!state.selectedAgentVaultId) {
      detailBody.appendChild(note("Select a vault above to load its agent registry."));
      return host;
    }

    detailBody.appendChild(note("Loading agents for " + state.selectedAgentVaultId + "…"));

    Promise.resolve()
      .then(function () { return state.api.client.getVault(state.selectedAgentVaultId); })
      .then(function (v) {
        detailBody.textContent = "";
        if (!v || typeof v.contractVersion !== "string") {
          detailBody.appendChild(note("The server returned no readable vault document for this id.", "hard"));
          return;
        }
        detailBody.appendChild(kv("Selected vault", state.selectedAgentVaultId));
        detailBody.appendChild(kv("Contract version", v.contractVersion));

        if (!Array.isArray(v.agents)) {
          detailBody.appendChild(note(
            "This vault's covenant version (" + v.contractVersion + ") does not carry a multi-agent registry — it has a single delegate" +
              (v.delegate ? " (" + v.delegate + ")" : "") +
              ". Multiple independent agents are a v0.4 covenant feature.",
            ""
          ));
          return;
        }
        if (!v.agents.length) {
          detailBody.appendChild(note("This vault's agent registry is empty."));
          return;
        }
        v.agents.forEach(function (a) {
          detailBody.appendChild(el("div", { class: "row" }, [
            kv("Agent", a.agentAddress || a.agentPk || "(unknown)"),
            kv("Max per spend (KAS)", a.maxPerSpendKas !== undefined ? String(a.maxPerSpendKas) : "unknown"),
            kv("Period budget (KAS)", a.periodBudgetKas !== undefined ? String(a.periodBudgetKas) : "unknown"),
            kv("Period spent (KAS)", a.periodSpentKas !== undefined ? String(a.periodSpentKas) : "unknown"),
            kv("Remaining this period (KAS)", a.remainingBudgetKas !== undefined ? String(a.remainingBudgetKas) : "unknown"),
            kv("Approval threshold (KAS)", a.approvalThresholdKas !== undefined ? String(a.approvalThresholdKas) : "unknown"),
            kv(
              "Recipient allowlist",
              Array.isArray(a.recipientAddresses) && a.recipientAddresses.length ? a.recipientAddresses.join(", ") : "(none)"
            )
          ]));
        });
      })
      .catch(function (e) {
        var d = state.api.describeError(e);
        detailBody.textContent = "";
        detailBody.appendChild(el("div", { class: "servererr" }, [
          el("div", { class: "servererr-head", text: d.kind + " — " + d.code }),
          full(d.text, "servererr-body")
        ]));
        if (d.kind === "TRANSPORT_FAILURE") detailBody.appendChild(note(d.retryNote, "hard"));
      });

    return host;
  }

  function screenApprovals() {
    return remoteScreen(
      "Approvals",
      "The pending approval queue. The approver never saw the original form, so the durable server request is the intent provenance — and every approval still passes through on-device verification before any signing affordance appears.",
      function (c) { return c.listRequests({ open: true }); },
      function (data) {
        var list = Array.isArray(data) ? data : (data && Array.isArray(data.requests) ? data.requests : []);
        return list.map(function (r) {
          var row = el("div", { class: "row" }, [
            kv("Request", r.requestId || r.id || "(unidentified)"),
            kv("Action", r.action || "unknown"),
            kv("State", r.state || r.status || "unknown")
          ]);
          row.appendChild(el("button", {
            class: "btn",
            text: "Verify this request on this device",
            onclick: function () { state.pendingRequest = r; go("verify"); }
          }));
          return row;
        });
      }
    );
  }

  function screenActivity() {
    return remoteScreen(
      "Activity",
      "The correlated audit feed: requested intent, verified manifest, policy state, approvals, signer authorization, txid and chain state. Read-only — a lens on the same correlation, never a second source of truth.",
      function (c) { return c.audit({ limit: 50 }); },
      function (data) {
        var list = Array.isArray(data) ? data : (data && Array.isArray(data.events) ? data.events : []);
        return list.map(function (ev) {
          return el("div", { class: "row" }, [
            kv("Event", ev.type || ev.event || "unknown"),
            kv("Vault", ev.vaultId || "—"),
            kv("Recorded", ev.createdAt || ev.at || "—")
          ]);
        });
      }
    );
  }

  function screenAlerts() {
    var host = el("div");
    host.appendChild(panel("Alerts", [
      note("Approval requested, approval granted, risk hold, reconciliation anomaly, pause/revoke executed."),
      unavailable("push notifications", state.platform.push.reason),
      el("div", { class: "card" }, [
        el("div", { class: "card-head", text: "Binding rules already fixed for when this is built" }),
        note("A push payload is untrusted, non-authoritative and VALUE-FREE: it may carry a request identifier and a category, never amounts, addresses, or approval outcomes. Everything displayed is re-fetched and re-verified in-app."),
        note("A notification may deep-link to a request DETAIL screen. It may never deep-link to a signing action, a confirmation, or a pre-approved state."),
        note("Delivery is best-effort. Push is not an alerting guarantee: time-critical states must also be visible on open."),
        note("Lock-screen previews are content-free by default; balances and counterparties never appear on a locked device.")
      ]),
      note("Because delivery is never guaranteed, this app is designed to be fully correct with notifications unavailable — which is its state today.", "hard")
    ]));
    return host;
  }

  /* --- Verify: the real verifier over a pasted/fetched document ------ */

  function screenVerify() {
    var host = el("div");

    if (!state.verification.available) {
      host.appendChild(panel("Verify", [
        unavailable("on-device verification", state.verification.unavailableReason),
        note("A verification error is a refusal. There is no reduced-verification mode.", "hard")
      ]));
      return host;
    }

    var input = el("textarea", {
      class: "doc",
      rows: "10",
      spellcheck: "false",
      placeholder: "Paste a verification input document: { \"request\": …, \"vault\": …, \"clientAction\": …, \"clientParams\": …, \"sessionNetwork\": \"testnet-10\", \"sessionXOnly\": … }"
    });
    if (state.pendingRequest) {
      input.value = JSON.stringify({ request: state.pendingRequest, sessionNetwork: state.settings.network }, null, 2);
    }

    var out = el("div", { class: "verify-out" });

    function runVerification() {
      out.textContent = "";
      var args;
      try {
        args = JSON.parse(input.value);
      } catch (e) {
        out.appendChild(UI.renderVerdict(VERIFICATION.refusal([
          { code: "VERIFY_INPUT_INVALID", detail: "the pasted text is not valid JSON: " + ((e && e.message) || String(e)) }
        ])));
        return;
      }
      var outcome = state.verification.verify(args);
      state.lastVerify = outcome;
      state.lastVerifyPayload = outcome && outcome.unsignedSafeJson ? outcome.unsignedSafeJson : null;
      out.appendChild(UI.renderVerdict(outcome));

      /* Rule 2: the signing affordance is ABSENT on a refusal, not
       * disabled. It is only ever appended inside this branch. */
      if (outcome.ok === true) {
        out.appendChild(el("button", {
          class: "btn primary",
          text: "Continue to signing",
          onclick: function () { state.airgapArgs = args; go("sign"); }
        }));
      }
    }

    host.appendChild(panel("Verify", [
      note("This runs the SAME reviewed verifier the web client runs — web/verify-intent.js over web/core-bundle.js, carried into this app byte-for-byte. Strict payload decode, manifest derivation, the full detector catalogue, Merkle root recomputation, fee/mass and successor-state recomputation, and the explanation text are all produced by that code, not by this app."),
      input,
      el("button", { class: "btn primary", text: "Verify on this device", onclick: runVerification }),
      out
    ]));
    return host;
  }

  /* --- Sign: QR/air-gap flow --------------------------------------- */

  function stopFrameLoop() {
    if (state.airgapTimer) { window.clearInterval(state.airgapTimer); state.airgapTimer = null; }
  }

  function screenSign() {
    stopFrameLoop();
    var host = el("div");

    var gate = AIRGAP.authorizeSigning({
      verification: state.lastVerify,
      unsignedSafeJson: state.lastVerifyPayload || ""
    });

    if (!gate.ok) {
      host.appendChild(panel("Sign", [
        note("The signing flow is reached only from a passing on-device verification bound to the exact transaction bytes."),
        el("div", { class: "verdict refuse" }, [
          el("div", { class: "verdict-head" }, [
            el("span", { class: "verdict-icon", "aria-hidden": "true", text: "⚠" }),
            el("span", { class: "verdict-title", text: "SIGNING BLOCKED" })
          ]),
          full(gate.code + ": " + gate.detail, "line")
        ]),
        note("This check runs independently of whatever the Verify screen displayed, so a defect in the interface alone cannot produce a signature.", "hard")
      ]));
      return host;
    }

    var built = AIRGAP.buildSigningRequestDocument({
      request: state.airgapArgs && state.airgapArgs.request,
      verification: state.lastVerify,
      network: state.settings.network,
      expectedSignerAddress: (state.airgapArgs && state.airgapArgs.expectedSignerAddress) || state.settings.signerAddress || ""
    });

    if (!built.ok) {
      host.appendChild(panel("Sign", [
        el("div", { class: "verdict refuse" }, [
          el("div", { class: "verdict-head" }, [
            el("span", { class: "verdict-icon", "aria-hidden": "true", text: "⚠" }),
            el("span", { class: "verdict-title", text: "SIGNING REQUEST NOT BUILT" })
          ]),
          full(built.code + ": " + built.detail, "line")
        ])
      ]));
      return host;
    }

    state.airgapDoc = built;

    var framed = QR.encodeFrames(built.documentText, { sha256Hex: sha256Hex });
    var outBlock = el("div", { class: "card" });
    outBlock.appendChild(el("div", { class: "card-head", text: "Step 1 — hand this request to the offline signer" }));
    outBlock.appendChild(kv("Document format", AIRGAP.SIGNING_REQUEST_FORMAT));
    outBlock.appendChild(kv("Transaction id", built.txId));
    outBlock.appendChild(kv("Network", state.settings.network));

    if (framed.ok) {
      outBlock.appendChild(kv("QR frames", String(framed.count) + " frame(s), document sha256 " + framed.docSha256));
      outBlock.appendChild(unavailable(
        "QR image rendering",
        "this build ships no QR encoder, so the frames below are shown as text rather than as scannable images — the framing itself is real and is what a QR encoder would carry"
      ));
      var frameView = full(framed.frames[0], "frame");
      outBlock.appendChild(frameView);
      var counter = note("Frame 1 of " + framed.count);
      outBlock.appendChild(counter);
      if (framed.count > 1) {
        state.airgapFrameIndex = 0;
        state.airgapTimer = window.setInterval(function () {
          state.airgapFrameIndex = (state.airgapFrameIndex + 1) % framed.count;
          frameView.textContent = framed.frames[state.airgapFrameIndex];
          counter.textContent = "Frame " + (state.airgapFrameIndex + 1) + " of " + framed.count;
        }, 900);
      }
    } else {
      outBlock.appendChild(unavailable("QR framing", framed.code + ": " + framed.detail));
    }

    outBlock.appendChild(el("button", {
      class: "btn",
      text: "Copy the full signing-request document",
      onclick: function () {
        PLATFORM.writeClipboard(built.documentText).then(function () {
          outBlock.appendChild(note("Copied. Save it as a file and run: node core/signer/adapters/cli/cli.js sign-tx --key <keyfile> --request-file <file>"));
        }).catch(function (e) {
          outBlock.appendChild(note("Clipboard unavailable (" + ((e && e.message) || e) + ") — select the document text below and copy it manually.", "hard"));
          outBlock.appendChild(full(built.documentText, "doc-dump"));
        });
      }
    }));

    /* Step 2 — bring the signature back. */
    var inBlock = el("div", { class: "card" });
    inBlock.appendChild(el("div", { class: "card-head", text: "Step 2 — bring the signed response back" }));
    inBlock.appendChild(unavailable("camera scanning", state.platform.camera.reason));
    inBlock.appendChild(unavailable("share sheet / Files", state.platform.file.reason));

    var respInput = el("textarea", {
      class: "doc",
      rows: "6",
      spellcheck: "false",
      placeholder: "Paste the signer's " + AIRGAP.SIGNED_TX_FORMAT + " document, or its PVQR1| frames one per line"
    });
    var respOut = el("div");

    inBlock.appendChild(respInput);
    inBlock.appendChild(el("button", {
      class: "btn primary",
      text: "Check the signed response",
      onclick: function () {
        respOut.textContent = "";
        var text = respInput.value.trim();

        /* Accept either the raw document or scanned PVQR1 frames. */
        if (text.indexOf(QR.FRAME_VERSION + "|") === 0) {
          var re = QR.createReassembler({ sha256Hex: sha256Hex });
          var frames = text.split(/\r?\n/).filter(function (l) { return l.trim(); });
          for (var i = 0; i < frames.length; i++) {
            var acc = re.accept(frames[i].trim());
            if (!acc.ok) { respOut.appendChild(refusalBox(acc.code, acc.detail)); return; }
          }
          var fin = re.finish();
          if (!fin.ok) { respOut.appendChild(refusalBox(fin.code, fin.detail)); return; }
          text = fin.text;
        }

        var parsedResp = AIRGAP.parseSignedResponseDocument(text, {
          expectedNetwork: state.settings.network,
          expectedSignerAddress: built.document.expectedSignerAddress,
          verification: state.lastVerify
        });
        if (!parsedResp.ok) { respOut.appendChild(refusalBox(parsedResp.code, parsedResp.detail)); return; }

        respOut.appendChild(el("div", { class: "verdict pass" }, [
          el("div", { class: "verdict-head" }, [
            el("span", { class: "verdict-icon", "aria-hidden": "true", text: "✓" }),
            el("span", { class: "verdict-title", text: "SIGNATURE BOUND TO THE VERIFIED TRANSACTION" })
          ]),
          full("Transaction id " + parsedResp.txId, "line"),
          full("Signed by " + parsedResp.address, "line")
        ]));
        respOut.appendChild(note(
          "This device confirmed provenance and transaction identity. It did NOT verify the signature bytes — the server's finalizer re-derives the frozen txid and runs a VM preflight before broadcast, and the covenant is the only security boundary.",
          "hard"
        ));
        respOut.appendChild(unavailable(
          "submit to the server",
          "submission needs an authenticated session, and the mobile session bootstrap is an open architecture decision — see Settings"
        ));
      }
    }));
    inBlock.appendChild(respOut);

    host.appendChild(panel("Sign — QR / air-gap to the offline CLI signer", [
      note("No key ever exists in this app. The signing request travels to a separate offline signer and only a signature comes back. That separation is what makes the verification on this device meaningful: the app that shows you the verdict cannot also produce the signature."),
      outBlock,
      inBlock
    ]));
    return host;
  }

  function refusalBox(code, detail) {
    return el("div", { class: "verdict refuse" }, [
      el("div", { class: "verdict-head" }, [
        el("span", { class: "verdict-icon", "aria-hidden": "true", text: "⚠" }),
        el("span", { class: "verdict-title", text: "REFUSED" })
      ]),
      full(code + ": " + detail, "line")
    ]);
  }

  /* --- Signers + capability limitations ----------------------------- */

  function screenSigners() {
    var host = el("div");
    var roster = state.roster;

    var adapters = el("div");
    roster.adapters.forEach(function (a) {
      var card = el("div", { class: "card" }, [
        el("div", { class: "card-head", text: a.label + "  —  " + a.role }),
        note(a.summary),
        kv("Implementation", a.implementation),
        kv("Transport", a.transport)
      ]);
      if (a.features) {
        var feats = Object.keys(a.features).map(function (k) { return k + ": " + (a.features[k] ? "yes" : "no"); }).join("   ");
        card.appendChild(kv("Declared capabilities", feats));
      } else {
        card.appendChild(kv("Declared capabilities", "declared only from a real runtime probe — nothing is assumed"));
      }
      card.appendChild(note(a.scaffoldNote));
      if (!a.offered) card.appendChild(unavailable(a.label, a.unavailableReason));
      adapters.appendChild(card);
    });

    var lims = el("div");
    roster.limitations.forEach(function (l) {
      lims.appendChild(el("div", { class: "card" }, [
        el("div", { class: "card-head", text: l.label + "  —  " + l.status }),
        note(l.body),
        note(l.alternative, "alt")
      ]));
    });

    host.appendChild(panel("Signers", [
      note("Every signer is listed with what it can and cannot do. Wallets PolicyVault cannot use are listed rather than hidden, with the concrete reason and the supported alternative."),
      adapters
    ]));
    host.appendChild(panel("Capability limitations", [
      note(roster.verificationRule, "hard"),
      lims
    ]));
    return host;
  }

  /* --- Wallet sign-in: QR-login bootstrap v1 ------------------------- *
   * (mobile/docs/session-bootstrap-DESIGN.md §3). Steps: (a) fetch a
   * challenge, (b) render it as the existing air-gap QR framing, (c)
   * accept the signature via the existing manual-paste transport, (d)
   * complete verify requesting bearer transport, (e) hold the token
   * memory-only (state.walletSessionToken — never state.settings, never
   * localStorage) and use it via the existing Authorization-header
   * client path (rebuildServices() above). Called from inside
   * screenSettings(), as one card within its host. */
  function screenWalletSignIn() {
    var pre = apiPreflight();
    if (pre) {
      return panel("Wallet sign-in (QR / air-gap)", [pre]);
    }

    if (state.walletSessionToken) {
      var out = el("div", { class: "card" }, [
        el("div", { class: "card-head", text: "Signed in" }),
        note("A wallet-bound bearer session is active for this run of the app. It is held in memory only and is lost when the app restarts.", "hard")
      ]);
      out.appendChild(el("button", {
        class: "btn",
        text: "Sign out",
        onclick: function () {
          var client = state.api.client;
          Promise.resolve()
            .then(function () { return client && client.request ? client.request("POST", "/auth/logout", { idempotencyKey: null }) : null; })
            .catch(function () { /* best-effort: still clear the local, memory-only token below */ })
            .then(function () {
              state.walletSessionToken = null;
              rebuildServices();
              go("settings");
            });
        }
      }));
      return panel("Wallet sign-in (QR / air-gap)", [out]);
    }

    var body = [
      note("Bootstrap v1: fetch a sign-in challenge, sign it with the offline CLI signer over the same air-gap QR framing used for transaction signing, then complete sign-in. No key ever exists in this app; the session token this creates is held in memory only for this run of the app and grants tenancy/read access only — never signing authority.")
    ];

    if (!state.authChallenge) {
      var addrInput = el("input", { class: "field", type: "text", value: state.authWalletAddressInput, placeholder: "kaspa:... or kaspatest:..." });
      body.push(el("label", { text: "Wallet address" }), addrInput);
      var getErr = el("div");
      body.push(el("button", {
        class: "btn primary",
        text: "Get sign-in challenge",
        onclick: function () {
          state.authWalletAddressInput = addrInput.value.trim();
          getErr.textContent = "";
          APIMOD.fetchAuthChallenge({ client: state.api.client, walletAddress: state.authWalletAddressInput }).then(function (r) {
            if (!r.ok) {
              getErr.textContent = "";
              getErr.appendChild(refusalBox("AUTH_CHALLENGE_UNAVAILABLE", r.reason));
              return;
            }
            state.authChallenge = r.challenge;
            state.authMessageSha256 = sha256Hex(r.challenge.message);
            go("settings");
          });
        }
      }));
      body.push(getErr);
      return panel("Wallet sign-in (QR / air-gap)", body);
    }

    /* A challenge is pending: render it for the offline signer, then
     * accept the signed response back. Mirrors screenSign()'s exact QR-
     * cycling + paste-back pattern. */
    var challenge = state.authChallenge;
    var outBlock = el("div", { class: "card" });
    outBlock.appendChild(el("div", { class: "card-head", text: "Step 1 — hand this challenge to your signer" }));
    outBlock.appendChild(kv("Wallet", challenge.walletAddress));
    outBlock.appendChild(kv("Network", challenge.networkId));

    var framed = QR.encodeFrames(challenge.message, { sha256Hex: sha256Hex });
    if (framed.ok) {
      outBlock.appendChild(kv("QR frames", String(framed.count) + " frame(s), document sha256 " + framed.docSha256));
      outBlock.appendChild(unavailable(
        "QR image rendering",
        "this build ships no QR encoder, so the frames below are shown as text rather than as scannable images — the framing itself is real and is what a QR encoder would carry"
      ));
      var frameView = full(framed.frames[0], "frame");
      outBlock.appendChild(frameView);
      var counter = note("Frame 1 of " + framed.count);
      outBlock.appendChild(counter);
      if (framed.count > 1) {
        state.airgapFrameIndex = 0;
        state.airgapTimer = window.setInterval(function () {
          state.airgapFrameIndex = (state.airgapFrameIndex + 1) % framed.count;
          frameView.textContent = framed.frames[state.airgapFrameIndex];
          counter.textContent = "Frame " + (state.airgapFrameIndex + 1) + " of " + framed.count;
        }, 900);
      }
    } else {
      outBlock.appendChild(unavailable("QR framing", framed.code + ": " + framed.detail));
    }

    outBlock.appendChild(el("button", {
      class: "btn",
      text: "Copy the challenge message",
      onclick: function () {
        PLATFORM.writeClipboard(challenge.message).then(function () {
          outBlock.appendChild(note("Copied. Save it as a file and run: node core/signer/adapters/cli/cli.js sign-message --key <keyfile> --message-file <file>"));
        }).catch(function (e) {
          outBlock.appendChild(note("Clipboard unavailable (" + ((e && e.message) || e) + ") — select the message below and copy it manually.", "hard"));
          outBlock.appendChild(full(challenge.message, "doc-dump"));
        });
      }
    }));
    outBlock.appendChild(el("button", {
      class: "btn",
      text: "Cancel this challenge",
      onclick: function () {
        state.authChallenge = null;
        state.authMessageSha256 = null;
        go("settings");
      }
    }));

    var inBlock = el("div", { class: "card" });
    inBlock.appendChild(el("div", { class: "card-head", text: "Step 2 — bring the signed response back" }));
    inBlock.appendChild(unavailable("camera scanning", state.platform.camera.reason));

    var respInput = el("textarea", {
      class: "doc",
      rows: "6",
      spellcheck: "false",
      placeholder: "Paste the signer's " + AIRGAP.AUTH_SIGNATURE_FORMAT + " document, or its PVQR1| frames one per line"
    });
    var respOut = el("div");
    inBlock.appendChild(respInput);
    inBlock.appendChild(el("button", {
      class: "btn primary",
      text: "Complete sign-in",
      onclick: function () {
        respOut.textContent = "";
        var text = respInput.value.trim();

        if (text.indexOf(QR.FRAME_VERSION + "|") === 0) {
          var re = QR.createReassembler({ sha256Hex: sha256Hex });
          var frames = text.split(/\r?\n/).filter(function (l) { return l.trim(); });
          for (var i = 0; i < frames.length; i++) {
            var acc = re.accept(frames[i].trim());
            if (!acc.ok) { respOut.appendChild(refusalBox(acc.code, acc.detail)); return; }
          }
          var fin = re.finish();
          if (!fin.ok) { respOut.appendChild(refusalBox(fin.code, fin.detail)); return; }
          text = fin.text;
        }

        var parsed = AIRGAP.parseAuthChallengeSignatureDocument(text, {
          expectedNetwork: state.settings.network,
          expectedMessageSha256: state.authMessageSha256,
          expectedWalletAddress: challenge.walletAddress
        });
        if (!parsed.ok) { respOut.appendChild(refusalBox(parsed.code, parsed.detail)); return; }

        APIMOD.completeAuthVerifyBearer({
          client: state.api.client,
          nonce: challenge.nonce,
          signature: parsed.signature,
          publicKey: parsed.publicKey,
          walletAddress: parsed.walletAddress
        }).then(function (r) {
          if (!r.ok) { respOut.appendChild(refusalBox("AUTH_VERIFY_FAILED", r.reason)); return; }
          state.walletSessionToken = r.token;
          state.authChallenge = null;
          state.authMessageSha256 = null;
          rebuildServices();
          go("settings");
        });
      }
    }));
    inBlock.appendChild(respOut);

    return panel("Wallet sign-in (QR / air-gap)", body.concat([outBlock, inBlock]));
  }

  /* --- Settings + build integrity ----------------------------------- */

  function screenSettings() {
    var host = el("div");

    var baseUrl = el("input", { class: "field", type: "url", value: state.settings.baseUrl, placeholder: "https://app.example.org" });
    var token = el("input", { class: "field", type: "password", value: state.settings.token, placeholder: "machine credential (optional, read-only testing)" });
    var network = el("select", { class: "field" });
    ["testnet-10", "mainnet"].forEach(function (n) {
      var opt = document.createElement("option");
      opt.value = n; opt.textContent = n;
      if (state.settings.network === n) opt.selected = true;
      network.appendChild(opt);
    });

    host.appendChild(panel("Server", [
      note("There is no default server. A financial client must never guess which deployment it is talking to."),
      el("label", { text: "PolicyVault server URL" }), baseUrl,
      el("label", { text: "Machine credential" }), token,
      note("The credential is held in this device's local storage for convenience only. This app never holds a signing key of any kind.", "hard"),
      el("label", { text: "Network" }), network,
      el("button", {
        class: "btn primary",
        text: "Save",
        onclick: function () {
          state.settings.baseUrl = baseUrl.value.trim();
          state.settings.token = token.value.trim();
          state.settings.network = network.value === "mainnet" ? "mainnet" : "testnet-10";
          saveSettings();
          rebuildServices();
          go("settings");
        }
      })
    ]));

    host.appendChild(screenWalletSignIn());

    /* Build integrity — a REAL re-hash of the packaged artifacts. */
    var integrity = el("div", { class: "card" }, [note("Re-hashing the packaged artifacts…")]);
    host.appendChild(panel("Build integrity", [
      note("The digests below are recomputed on this device from the packaged files, then compared with the pins generated from the repository sources. Compare them against the repository to confirm this app runs the reviewed verifier."),
      kv("Host", state.platform.host.platform + " (" + state.platform.host.engine + ")"),
      integrity
    ]));

    PLATFORM.readPackagedText("vendor-pins.json")
      .then(function (text) { return JSON.parse(text); })
      .then(function (pins) {
        state.pins = pins;
        return INTEGRITY.verifyPackagedArtifacts({
          pins: pins,
          sha256Hex: sha256Hex,
          readText: function (dest) { return PLATFORM.readPackagedText(dest.replace(/^www\//, "")); }
        });
      })
      .then(function (result) {
        integrity.textContent = "";
        integrity.appendChild(el("div", {
          class: result.ok ? "verdict pass" : "verdict refuse"
        }, [
          el("div", { class: "verdict-head" }, [
            el("span", { class: "verdict-icon", "aria-hidden": "true", text: result.ok ? "✓" : "⚠" }),
            el("span", { class: "verdict-title", text: result.ok ? "PACKAGED ARTIFACTS MATCH THEIR PINS" : "PACKAGED ARTIFACTS DO NOT MATCH" })
          ])
        ]));
        if (!result.ok && result.detail) integrity.appendChild(full(result.detail, "line"));
        result.artifacts.forEach(function (a) {
          integrity.appendChild(el("div", { class: "sub" }, [
            el("div", { class: "sub-head", text: (a.ok ? "OK  " : "FAIL  ") + a.dest }),
            kv("From repository source", a.source + "  sha256:" + a.sourceSha256),
            kv("Packaged bytes sha256", a.actualSha256 || "(unreadable)"),
            a.problem ? note(a.problem, "hard") : note("matches the release pin")
          ]));
        });
        integrity.appendChild(note(
          "This proves the packaged files match their pins as read by this running code. It is not an attestation: a compromised build can lie about any screen, including this one. The covenant remains the only security boundary.",
          "hard"
        ));
      })
      .catch(function (e) {
        integrity.textContent = "";
        integrity.appendChild(refusalBox("INTEGRITY_UNAVAILABLE", "could not verify the packaged artifacts: " + ((e && e.message) || String(e)) + " — an unreadable integrity check is a failure, never a pass"));
      });

    return host;
  }

  /* ------------------------------------------------------------------ */
  /* Router                                                              */
  /* ------------------------------------------------------------------ */

  var RENDER = {
    vaults: screenVaults,
    agents: screenAgents,
    approvals: screenApprovals,
    activity: screenActivity,
    alerts: screenAlerts,
    verify: screenVerify,
    sign: screenSign,
    signers: screenSigners,
    settings: screenSettings
  };

  function go(id) {
    stopFrameLoop();
    state.screen = RENDER[id] ? id : "vaults";
    render();
  }

  function render() {
    var nav = document.getElementById("nav");
    var main = document.getElementById("main");
    nav.textContent = "";
    SCREENS.forEach(function (s) {
      nav.appendChild(el("button", {
        class: "tab" + (state.screen === s.id ? " active" : ""),
        text: s.label,
        onclick: function () { go(s.id); }
      }));
    });
    main.textContent = "";
    main.appendChild(RENDER[state.screen]());
  }

  function boot() {
    rebuildServices();

    var banner = document.getElementById("banner");
    banner.textContent = "SCAFFOLD BUILD — NOT PRODUCTION-CAPABLE. Read/coordinate + on-device verification only.";

    if (!state.verification.available) {
      banner.textContent = "PACKAGED VERIFIER UNAVAILABLE — every verification on this device refuses. " + state.verification.unavailableReason;
      banner.className = "banner bad";
    }

    render();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
