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
    /* the last verification outcome and the payload it is bound to */
    lastVerify: null,
    lastVerifyPayload: null,
    /* air-gap session */
    airgapDoc: null,
    airgapFrames: null,
    airgapFrameIndex: 0,
    airgapTimer: null
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
      token: state.settings.token || undefined,
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

  function screenAgents() {
    var host = el("div");
    host.appendChild(panel("Agents", [
      note("Per-agent policy, per-spend caps, period budgets and recipient allowlists are read from each vault's detail document."),
      unavailable(
        "agent detail",
        "Agent policy is nested inside a vault document, so this screen needs a selected vault. Vault selection is not wired in this scaffold — open Vaults to confirm server reachability first."
      ),
      note(
        "When it is wired, the FULL leaf data must be present: a vault view that cannot be re-hashed to the covenant-committed agent-registry root shows a verification-unavailable state, never a silent pass.",
        "hard"
      )
    ]));
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
