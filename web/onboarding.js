"use strict";

/*
 * PolicyVault first-run walkthrough ("How PolicyVault works") — adoption
 * UX track. PRESENTATION ONLY.
 *
 * What this module is:
 *   - a skippable, replayable, keyboard-operable VISUAL walkthrough (six
 *     steps) that shows AI / App → PolicyVault → Covenant → Kaspa, the
 *     four-line authority statement, owner → vault creation with custody
 *     staying in the wallet, rules as chips and meters, bounded delegation
 *     as an envelope, accepted-versus-refused requests as animated gauges,
 *     and the wallet-versus-PolicyVault distinction;
 *   - a persistent "How PolicyVault works" entry on the home / signed-out
 *     experience and a replay entry under the header Help menu;
 *   - a tiny piece of benign per-browser state
 *     ({ onboardingVersion, completed, dontShowAgain }) in localStorage,
 *     every access wrapped so the app is unaffected when storage throws.
 *
 * Visual language (owner direction, 2026-09-02): local HTML / CSS / inline
 * SVG only — no remote asset, no analytics, no video, no GIF; every colour
 * derives from the app's theme tokens (dark + light compatible); every
 * animation is CSS whose FINAL state is the static default, so the diagrams
 * read identically under prefers-reduced-motion; fixed-pitch diagrams scale
 * to narrow viewports; a "Replay animation" control is keyboard-reachable.
 * Illustrative numbers (5 KAS cap, 25 KAS per day, approval above 3 KAS)
 * are EXAMPLES, not defaults, limits, or recommendations.
 *
 * What this module is NOT — and must never become:
 *   - it never gates functionality: nothing in the app awaits, reads, or
 *     depends on onboarding state; the walkthrough mounts only AFTER boot
 *     has settled (web/app.js hooks `boot().finally(...)`), and every
 *     control (Skip on step 1, ✕, Escape, backdrop) closes it;
 *   - it never touches a request / verify / sign / network code path, never
 *     performs a fetch, never asks for a transaction, never handles keys,
 *     and never implies that PolicyVault itself signs;
 *   - it carries no input other than the "Don't show this again" checkbox.
 *
 * Browser: loaded last by web/index.html and exposed as
 * window.PolicyVaultOnboarding. Node: `require("../onboarding.js")` returns
 * the same surface plus `create()` for tests with a minimal DOM.
 */
(function () {
  const ONBOARDING_VERSION = 1;
  const STORAGE_KEY = "pv.onboarding";
  const DOCS_BASE = "https://docs.policy-vault.org";
  const SVG_NS = "http://www.w3.org/2000/svg";

  /* The authority statement — verbatim, prominent, four lines. */
  const CORE_MESSAGE = Object.freeze([
    "AI MAY REQUEST.",
    "POLICYVAULT DETERMINISTICALLY DECIDES.",
    "THE COVENANT ENFORCES.",
    "SIGNERS RETAIN CUSTODY."
  ]);

  /* The flow, top to bottom: who acts, what each layer does, and what
   * travels down to the next layer. */
  const FLOW = Object.freeze([
    { name: "AI / App", role: "requests a spend", icon: "agent", edge: "request" },
    { name: "PolicyVault", role: "decides: authorized or refused", icon: "shield", edge: "authorized transaction" },
    { name: "Covenant", role: "enforces the rules on-chain", icon: "contract", edge: "enforcement" },
    { name: "Kaspa", role: "consensus rejects anything outside them", icon: "chain", edge: null }
  ]);

  const WALLET_QUESTION = 'A wallet asks: "Can this key sign?"';
  const POLICYVAULT_QUESTION = 'PolicyVault asks: "Is this action authorized?"';

  /* ONE illustrative vault shared by steps 3, 4 and 5 so the pictures agree
   * with each other. Example values only. */
  const EXAMPLE = Object.freeze({
    capKas: 5, // per-spend maximum
    dailyKas: 25, // budget per period
    usedTodayKas: 9, // illustrative consumption of today's budget
    approvalAboveKas: 3, // spends above this need approver signatures
    approversRequired: 2,
    approversTotal: 3,
    recipients: Object.freeze(["A", "B"]),
    scaleKas: 10 // gauge width in KAS for the per-spend pictures
  });

  const RULES = Object.freeze([
    { id: "cap", chip: `Per spend ≤ ${EXAMPLE.capKas} KAS`, caption: "a hard cap on any single spend" },
    { id: "budget", chip: `Daily budget ≤ ${EXAMPLE.dailyKas} KAS`, caption: "a cumulative cap per period, counted in Kaspa consensus time (DAA score), so wall-clock duration is approximate" },
    { id: "recipients", chip: "Approved recipients only", caption: "the agent may only pay addresses on the list" },
    { id: "approval", chip: `Approval above ${EXAMPLE.approvalAboveKas} KAS`, caption: `larger spends wait for ${EXAMPLE.approversRequired}-of-${EXAMPLE.approversTotal} approver signatures; approvers cannot spend or act as the owner` }
  ]);

  const AGENT_MAY = Object.freeze(["request or spend within policy"]);
  const AGENT_MAY_NOT = Object.freeze(["exceed the cap", "exceed the budget", "expand the policy", "obtain owner custody"]);

  /* Step 5 — the same vault, four requests. Verdict order is part of the
   * tested contract: ACCEPTED, REFUSED, REFUSED, NEEDS APPROVAL. */
  const EXAMPLES = Object.freeze([
    {
      verdict: "ACCEPTED",
      amountKas: 2,
      recipient: "A",
      title: "Agent requests 2 KAS to recipient A",
      facts: [
        { ok: true, text: `within the ${EXAMPLE.capKas} KAS cap` },
        { ok: true, text: "recipient A approved" },
        { ok: true, text: "within today's budget" },
        { ok: true, text: `at or below the ${EXAMPLE.approvalAboveKas} KAS approval threshold` }
      ],
      lines: ["Authorized: the agent signs with its own key and the covenant accepts. PolicyVault never signs."]
    },
    {
      verdict: "REFUSED",
      amountKas: 8,
      recipient: "A",
      title: "Agent requests 8 KAS to recipient A",
      facts: [{ ok: false, text: `exceeds the ${EXAMPLE.capKas} KAS cap` }, { ok: true, text: "recipient A approved" }],
      lines: ["Refused before any signature is requested — and even a correctly signed 8 KAS transaction would be rejected by Kaspa consensus."]
    },
    {
      verdict: "REFUSED",
      amountKas: 1,
      recipient: null,
      title: "Agent requests 1 KAS to an address not on the list",
      facts: [{ ok: true, text: `within the ${EXAMPLE.capKas} KAS cap` }, { ok: false, text: "recipient not approved" }],
      lines: ["Destination is not an allowed recipient. Refused, however small the amount."]
    },
    {
      verdict: "NEEDS APPROVAL",
      amountKas: 4,
      recipient: "B",
      title: "Agent requests 4 KAS to recipient B",
      facts: [
        { ok: true, text: `within the ${EXAMPLE.capKas} KAS cap` },
        { ok: true, text: "recipient B approved" },
        { ok: null, text: `above the ${EXAMPLE.approvalAboveKas} KAS approval threshold` }
      ],
      lines: [`The vault's approval policy applies: ${EXAMPLE.approversRequired} of ${EXAMPLE.approversTotal} approver wallets must sign. Nothing moves without them.`]
    }
  ]);

  /*
   * Walkthrough content. Block types: art (an illustrated figure: flow,
   * create, rules, delegate, examples, distinction), core (the four-line
   * statement), p, note, ul, docs (a link to the public documentation;
   * opens in a new tab, no opener/referrer).
   * Copy rules: PolicyVault is NOT a wallet; it never custodies funds; it
   * never signs; it claims nothing it cannot back; free forever, voluntary
   * support only, no nagging.
   */
  const STEPS = Object.freeze([
    {
      id: "flow",
      title: "What PolicyVault is",
      lead:
        "PolicyVault is a non-custodial treasury layer for Kaspa. You keep your keys and your wallet; " +
        "a covenant on Kaspa L1 enforces the spending rules you set; PolicyVault decides deterministically " +
        "whether each request fits those rules.",
      blocks: [
        { type: "art", kind: "flow" },
        { type: "core" },
        {
          type: "note",
          text:
            "PolicyVault is not a wallet and never holds your funds. Every transaction is signed inside your own " +
            "wallet (KasWare) after you review it — PolicyVault prepares and checks; it never signs for you."
        }
      ]
    },
    {
      id: "create",
      title: "Create and control a vault",
      lead: "Connect KasWare and open Create Vault. The connected wallet becomes the vault owner — and custody never leaves it.",
      blocks: [
        { type: "art", kind: "create" },
        {
          type: "ul",
          items: [
            "Name the vault, choose the deposit, and set a fee reserve — the reserve pays permitted agent transaction fees without reducing protected principal.",
            "Review the exact policy before anything is signed. The owner wallet signs the creation transaction; PolicyVault only prepares it. Funding and later top-ups are ordinary Kaspa transactions from your own wallet.",
            "The vault lives as a covenant-locked output on Kaspa L1. The owner keeps break-glass controls on-chain: Pause, Remove agent, Rotate key, and Close & recover."
          ]
        },
        { type: "docs", slug: "fee-reserve", label: "Learn more about the fee reserve" }
      ]
    },
    {
      id: "rules",
      title: "Set bounded rules",
      lead: "Rules are written into the covenant, so they hold on-chain even if this app or its server were compromised. Illustrative values:",
      blocks: [
        { type: "art", kind: "rules" },
        {
          type: "note",
          text: "Rules are bounds, not suggestions: a transaction outside them is rejected by Kaspa consensus, however it was signed."
        },
        { type: "docs", slug: "per-transaction-limit", label: "Learn more about the spending rules" }
      ]
    },
    {
      id: "delegate",
      title: "Delegate bounded authority",
      lead: "An agent — an AI, a service, or a teammate — holds its own key and may request spends within the rules, and nothing beyond them.",
      blocks: [
        { type: "art", kind: "delegate" },
        {
          type: "note",
          text:
            "Delegation means bounded authority, not shared keys. Agents never see owner keys; PolicyVault never sees any key. " +
            "Inside the bounds the agent signs its own spends; outside them nothing it signs is valid."
        },
        { type: "docs", slug: "agent-delegate", label: "Learn more about agent delegates" }
      ]
    },
    {
      id: "examples",
      title: "Accepted versus refused",
      lead:
        `The same illustrative vault — maximum ${EXAMPLE.capKas} KAS per spend, ${EXAMPLE.dailyKas} KAS per day, recipients A and B allowed, ` +
        `approval required above ${EXAMPLE.approvalAboveKas} KAS — and four requests, each evaluated deterministically.`,
      blocks: [
        { type: "art", kind: "examples" },
        {
          type: "note",
          text:
            "Decisions are computed from the vault's exact live state, never guessed. When that state cannot be verified, PolicyVault fails closed and says so. " +
            "An authorized request is signed by the agent's own wallet — PolicyVault itself never signs."
        },
        {
          type: "p",
          text: "PolicyVault is free to use, including commercial use. Voluntary KAS donations are welcome under Support — they never unlock anything."
        }
      ]
    },
    {
      id: "distinction",
      title: "A wallet versus PolicyVault",
      lead: "Two different questions. A wallet can only answer the first one.",
      blocks: [
        { type: "art", kind: "distinction" },
        {
          type: "note",
          text:
            "PolicyVault answers the second question and nothing else: it prepares and checks, your wallet signs, the covenant enforces. " +
            "It never signs for you and never holds your funds."
        }
      ]
    }
  ]);

  /* ---------------- benign persisted state ---------------- */

  /*
   * Storage access is wrapped at EVERY step (the property access itself can
   * throw — privacy modes, sandboxed frames). Unavailable storage means
   * "cannot remember", so the walkthrough never auto-shows (it would
   * otherwise nag on every load) — replay still works.
   */
  function storageOf(win) {
    return {
      read() {
        try {
          const raw = win.localStorage.getItem(STORAGE_KEY);
          return { available: true, raw };
        } catch (_) {
          return { available: false, raw: null };
        }
      },
      write(value) {
        try {
          win.localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
          return true;
        } catch (_) {
          return false;
        }
      }
    };
  }

  function parseRecord(raw) {
    if (typeof raw !== "string" || !raw) return null;
    let v;
    try {
      v = JSON.parse(raw);
    } catch (_) {
      return null;
    }
    if (!v || typeof v !== "object" || !Number.isInteger(v.onboardingVersion) || v.onboardingVersion < 1) return null;
    return { onboardingVersion: v.onboardingVersion, completed: v.completed === true, dontShowAgain: v.dontShowAgain === true };
  }

  /* ---------------- DOM helpers (tiny, shim-friendly) ---------------- */

  function el(doc, tag, attrs, children) {
    const node = doc.createElement(tag);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        const v = attrs[k];
        if (v === undefined || v === null || v === false) continue;
        if (k === "text") node.textContent = String(v);
        else if (k === "className") node.className = String(v);
        else node.setAttribute(k, v === true ? "" : String(v));
      }
    }
    if (children) for (const c of children) if (c) node.appendChild(c);
    return node;
  }

  /* Inline SVG (namespaced in browsers; plain elements in the test shim).
   * Every icon is decorative: aria-hidden, colour from currentColor only. */
  function svg(doc, tag, attrs, children) {
    const node = typeof doc.createElementNS === "function" ? doc.createElementNS(SVG_NS, tag) : doc.createElement(tag);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        const v = attrs[k];
        if (v === undefined || v === null || v === false) continue;
        if (k === "text") node.textContent = String(v);
        else node.setAttribute(k, v === true ? "" : String(v));
      }
    }
    if (children) for (const c of children) if (c) node.appendChild(c);
    return node;
  }

  /* Icon paths (24×24 grid, stroked with currentColor). */
  const ICONS = Object.freeze({
    agent: ["M4 8h16v10H4z", "M12 4v4", "M9.5 12.5h.01", "M14.5 12.5h.01", "M9 15.5h6"],
    shield: ["M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6z", "M9 12l2 2 4-4"],
    contract: ["M7 3h7l4 4v14H7z", "M14 3v4h4", "M9.5 12h5", "M9.5 15.5h5"],
    chain: ["M12 3l7.8 4.5v9L12 21l-7.8-4.5v-9z", "M12 8v8", "M8.5 10l7 4", "M15.5 10l-7 4"],
    person: ["M12 4.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z", "M5 20c0-4 3-6 7-6s7 2 7 6"],
    key: ["M8 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z", "M11.5 12H21", "M17 12v3", "M20 12v2.5"],
    wallet: ["M3 7h15a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H3z", "M3 7V5.5A1.5 1.5 0 0 1 4.5 4H16v3", "M15 13h3"]
  });

  function icon(doc, name) {
    const paths = ICONS[name] || [];
    return svg(
      doc,
      "svg",
      { class: "pv-onb-ico", viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round" },
      paths.map((d) => svg(doc, "path", { d }))
    );
  }

  const seq = (i) => `pv-onb-seq-${Math.min(i + 1, 4)}`;
  const verdictClass = (v) => (v === "ACCEPTED" ? "ok" : v === "REFUSED" ? "bad" : "warn");
  const pct = (kas, scale) => `${Math.round((kas / scale) * 1000) / 10}%`;

  function docsLink(doc, slug, label) {
    return el(doc, "a", {
      className: "pv-onb-docs",
      href: `${DOCS_BASE}/${slug}/`,
      target: "_blank",
      rel: "noopener noreferrer",
      text: label + " ↗"
    });
  }

  /* An illustrated figure: a labelled group (its text stays readable in DOM
   * order; icons, wires and packets are decorative) plus a keyboard-reachable
   * "Replay animation" control that simply re-renders the figure, which
   * restarts every CSS animation. CSS hides that control under
   * prefers-reduced-motion, where no animation runs and the static (final)
   * state carries the whole picture. */
  function figure(doc, kind, label, build) {
    const wrap = el(doc, "div", { className: `pv-onb-art pv-onb-art-${kind}` });
    const paint = () => {
      wrap.textContent = "";
      wrap.appendChild(el(doc, "div", { className: "pv-onb-fig", role: "group", "aria-label": label }, build(doc)));
      const replay = el(doc, "button", { className: "pv-onb-art-replay", type: "button", text: "↻ Replay animation" });
      replay.addEventListener("click", paint);
      wrap.appendChild(replay);
    };
    paint();
    return wrap;
  }

  function chip(doc, cls, text) {
    return el(doc, "span", { className: `pv-onb-chip ${cls}`, text });
  }

  function box(doc, cls, iconName, title, sub, extra) {
    return el(doc, "div", { className: `pv-onb-box ${cls}` }, [
      el(doc, "span", { className: "pv-onb-box-ico" }, [icon(doc, iconName)]),
      el(doc, "span", { className: "pv-onb-box-title", text: title }),
      sub ? el(doc, "span", { className: "pv-onb-box-sub", text: sub }) : null,
      ...(extra || [])
    ]);
  }

  /* Vertical connector between two boxes: a wire, an arrowhead, a label,
   * and optionally a packet that drops along it. */
  function link(doc, cls, label, packetText) {
    return el(doc, "div", { className: `pv-onb-link ${cls}` }, [
      packetText ? el(doc, "span", { className: "pv-onb-link-packet", "aria-hidden": "true" }) : null,
      el(doc, "span", { className: "pv-onb-link-label", text: label }),
      packetText ? el(doc, "span", { className: "pv-onb-link-packet-text", text: packetText }) : null
    ]);
  }

  /* A horizontal meter: segments (from/to in KAS) and marks (a tick with an
   * optional tag above or below the track). Widths are percentages of the
   * meter's own scale. */
  function meter(doc, spec) {
    const scale = spec.scaleKas;
    const parts = [];
    for (const s of spec.segments || []) {
      parts.push(el(doc, "span", { className: `pv-onb-meter-fill ${s.cls}`, style: `left:${pct(s.fromKas, scale)};width:${pct(s.toKas - s.fromKas, scale)}` }));
    }
    for (const m of spec.marks || []) {
      parts.push(el(doc, "span", { className: `pv-onb-meter-mark ${m.cls}`, style: `left:${pct(m.atKas, scale)}` }));
      if (m.tag) parts.push(el(doc, "span", { className: `pv-onb-meter-tag ${m.cls} ${m.below ? "below" : "above"}`, style: `left:${pct(m.atKas, scale)}`, text: m.tag }));
    }
    const hasBelow = (spec.marks || []).some((m) => m.tag && m.below);
    return el(doc, "div", { className: `pv-onb-meter${spec.tight ? " tight" : ""}${hasBelow ? " has-below" : ""}` }, [
      el(doc, "div", { className: "pv-onb-meter-track", "aria-hidden": "true" }, parts),
      el(doc, "div", { className: "pv-onb-meter-scale" }, [
        el(doc, "span", { text: spec.lo || "0" }),
        el(doc, "span", { text: spec.hi || `${scale} KAS` })
      ])
    ]);
  }

  /* ---------------- figures ---------------- */

  /* STEP 1 — system flow: four layers on a vertical wire; a packet travels
   * AI / App → PolicyVault → Covenant → Kaspa and each layer lights as it
   * arrives; the edge labels (request / authorized transaction /
   * enforcement) fade in as the packet passes. */
  function buildFlow(doc) {
    const nodes = [el(doc, "span", { className: "pv-onb-wire", "aria-hidden": "true" }), el(doc, "span", { className: "pv-onb-packet", "aria-hidden": "true" })];
    FLOW.forEach((stage, i) => {
      nodes.push(
        el(doc, "div", { className: `pv-onb-stage ${seq(i)}` }, [
          el(doc, "span", { className: "pv-onb-node", "aria-hidden": "true" }, [icon(doc, stage.icon)]),
          el(doc, "div", { className: "pv-onb-stage-name", text: stage.name }),
          el(doc, "div", { className: "pv-onb-stage-role", text: stage.role })
        ])
      );
      if (stage.edge) {
        nodes.push(
          el(doc, "div", { className: `pv-onb-arrow ${seq(i)}` }, [
            el(doc, "span", { className: "pv-onb-arrow-head", "aria-hidden": "true" }),
            el(doc, "span", { className: "pv-onb-arrow-label", text: stage.edge })
          ])
        );
      }
    });
    return [el(doc, "div", { className: "pv-onb-flow" }, nodes)];
  }

  /* STEP 2 — create / control: OWNER (wallet, keys stay) → POLICYVAULT
   * VAULT (covenant-locked output), a signed transaction dropping down the
   * wire, then the custody boundary strip: what stays in the wallet versus
   * what PolicyVault does. */
  function buildCreate(doc) {
    return [
      el(doc, "div", { className: "pv-onb-stack" }, [
        box(doc, `pv-onb-box-owner ${seq(0)}`, "wallet", "OWNER", "your wallet (KasWare) — creates, reviews, signs", [chip(doc, "rule ico", "keys stay here")]),
        link(doc, seq(1), "creates · reviews · signs in the wallet", "signed transaction"),
        box(doc, `pv-onb-box-vault ${seq(2)}`, "contract", "POLICYVAULT VAULT", "a covenant-locked output on Kaspa L1", [
          el(doc, "span", { className: "pv-onb-chips" }, [chip(doc, "dim", "policy"), chip(doc, "dim", "principal"), chip(doc, "dim", "fee reserve")])
        ]),
        el(doc, "div", { className: `pv-onb-custody ${seq(3)}` }, [
          el(doc, "div", {}, [el(doc, "b", { text: "Your wallet" }), el(doc, "span", { text: "keys · signing · custody" })]),
          el(doc, "div", { className: "pv-onb-custody-line", "aria-hidden": "true" }, [el(doc, "span", { className: "pv-onb-custody-tag", text: "custody boundary" })]),
          el(doc, "div", {}, [el(doc, "b", { text: "PolicyVault" }), el(doc, "span", { text: "prepares · verifies · never signs · never holds keys" })])
        ])
      ])
    ];
  }

  /* STEP 3 — rules as chips and meters instead of paragraphs. */
  function buildRules(doc) {
    const rows = RULES.map((r, i) => {
      let visual = null;
      if (r.id === "cap") {
        visual = meter(doc, {
          scaleKas: EXAMPLE.scaleKas,
          segments: [{ fromKas: 0, toKas: EXAMPLE.capKas, cls: "ok" }, { fromKas: EXAMPLE.capKas, toKas: EXAMPLE.scaleKas, cls: "over" }],
          marks: [{ atKas: EXAMPLE.capKas, cls: "cap", tag: `cap ${EXAMPLE.capKas} KAS` }]
        });
      } else if (r.id === "budget") {
        visual = meter(doc, {
          scaleKas: EXAMPLE.dailyKas,
          hi: `${EXAMPLE.dailyKas} KAS / day`,
          segments: [{ fromKas: 0, toKas: EXAMPLE.usedTodayKas, cls: "accent" }],
          marks: [{ atKas: EXAMPLE.usedTodayKas, cls: "accent", tag: `${EXAMPLE.usedTodayKas} KAS used today`, below: true }]
        });
      } else if (r.id === "recipients") {
        visual = el(doc, "div", { className: "pv-onb-chips" }, [
          ...EXAMPLE.recipients.map((name) => chip(doc, "ok", `recipient ${name} ✓`)),
          chip(doc, "bad dim", "anyone else ✕")
        ]);
      } else if (r.id === "approval") {
        const people = [];
        for (let k = 0; k < EXAMPLE.approversTotal; k++) {
          people.push(el(doc, "span", { className: `pv-onb-approver${k < EXAMPLE.approversRequired ? " on" : ""}`, "aria-hidden": "true" }, [icon(doc, "person")]));
        }
        visual = el(doc, "div", { className: "pv-onb-chips" }, [
          el(doc, "span", { className: "pv-onb-approvers" }, people),
          chip(doc, "warn", `${EXAMPLE.approversRequired} of ${EXAMPLE.approversTotal} approvers sign above ${EXAMPLE.approvalAboveKas} KAS`)
        ]);
      }
      return el(doc, "div", { className: `pv-onb-rule ${seq(i)}` }, [
        el(doc, "div", { className: "pv-onb-rule-head" }, [chip(doc, "rule", r.chip), el(doc, "span", { className: "pv-onb-rule-cap", text: r.caption })]),
        visual
      ]);
    });
    return [el(doc, "div", { className: "pv-onb-rules" }, rows)];
  }

  /* STEP 4 — bounded delegation: OWNER → AGENT inside a visibly bounded
   * policy envelope; what the agent may do sits inside, what it may not do
   * sits outside; a probe dot repeatedly hits the envelope wall and stops. */
  function buildDelegate(doc) {
    return [
      el(doc, "div", { className: "pv-onb-deleg" }, [
        box(doc, `pv-onb-box-owner ${seq(0)}`, "person", "OWNER", "holds full authority and custody", [chip(doc, "rule ico", "keys stay here")]),
        link(doc, seq(1), "delegates bounded authority", "bounded authority"),
        el(doc, "div", { className: `pv-onb-envelope ${seq(2)}` }, [
          el(doc, "span", { className: "pv-onb-env-tag", text: "policy envelope" }),
          box(doc, "pv-onb-box-agent", "agent", "AGENT", "an AI, a service, or a teammate — with its own key"),
          el(doc, "div", { className: "pv-onb-may-h", text: "Agent may" }),
          el(doc, "ul", { className: "pv-onb-may" }, AGENT_MAY.map((t) => el(doc, "li", { className: "pv-onb-chip ok", text: `✓ ${t}` }))),
          el(doc, "span", { className: "pv-onb-probe", "aria-hidden": "true" })
        ]),
        el(doc, "div", { className: `pv-onb-maynot-wrap ${seq(3)}` }, [
          el(doc, "div", { className: "pv-onb-may-h", text: "Agent may not" }),
          el(doc, "ul", { className: "pv-onb-maynot" }, AGENT_MAY_NOT.map((t) => el(doc, "li", { className: "pv-onb-chip bad dim", text: `✕ ${t}` })))
        ])
      ])
    ];
  }

  /* STEP 5 — accepted versus refused: one card per request; the request
   * bar grows against the cap, then the verdict stamps in. The portion of a
   * request beyond the cap is hatched red. */
  function buildExamples(doc) {
    const cards = EXAMPLES.map((x, i) => {
      const cls = verdictClass(x.verdict);
      const within = Math.min(x.amountKas, EXAMPLE.capKas);
      const segments = [{ fromKas: 0, toKas: within, cls }];
      if (x.amountKas > EXAMPLE.capKas) segments.push({ fromKas: EXAMPLE.capKas, toKas: x.amountKas, cls: "over" });
      const gauge = meter(doc, {
        scaleKas: EXAMPLE.scaleKas,
        tight: true,
        segments,
        marks: [
          { atKas: EXAMPLE.approvalAboveKas, cls: "thr", tag: `approval > ${EXAMPLE.approvalAboveKas} KAS`, below: true },
          { atKas: EXAMPLE.capKas, cls: "cap", tag: `cap ${EXAMPLE.capKas} KAS` }
        ]
      });
      const facts = el(doc, "div", { className: "pv-onb-facts" }, x.facts.map((f) => chip(doc, `fact ${f.ok === true ? "ok" : f.ok === false ? "bad" : "warn"}`, `${f.ok === true ? "✓" : f.ok === false ? "✕" : "!"} ${f.text}`)));
      return el(doc, "div", { className: `pv-onb-example ${cls} ${seq(i)}` }, [
        el(doc, "div", { className: "pv-onb-example-head" }, [
          el(doc, "span", { className: `pv-onb-verdict ${cls}`, text: x.verdict }),
          el(doc, "span", { className: "pv-onb-example-title", text: x.title })
        ]),
        gauge,
        facts,
        ...x.lines.map((t) => el(doc, "div", { className: "pv-onb-example-line", text: t }))
      ]);
    });
    return [el(doc, "div", { className: "pv-onb-examples" }, cards)];
  }

  /* STEP 6 — the key distinction, then the composition:
   * PolicyVault policy + external signer + Kaspa covenant enforcement. */
  function splitQuestion(q) {
    const i = q.indexOf(": ");
    return i < 0 ? ["", q] : [q.slice(0, i + 2), q.slice(i + 2)];
  }

  function buildDistinction(doc) {
    const [wWho, wQ] = splitQuestion(WALLET_QUESTION);
    const [pWho, pQ] = splitQuestion(POLICYVAULT_QUESTION);
    const card = (cls, iconName, head, who, q, sub) =>
      el(doc, "div", { className: cls }, [
        el(doc, "div", { className: "pv-onb-cmp-head" }, [icon(doc, iconName), el(doc, "span", { text: head })]),
        el(doc, "div", { className: "pv-onb-cmp-who", text: who }),
        el(doc, "div", { className: "pv-onb-cmp-q", text: q }),
        el(doc, "div", { className: "pv-onb-cmp-sub", text: sub })
      ]);
    const tile = (i, iconName, text) => el(doc, "span", { className: `pv-onb-sum-tile ${seq(i)}` }, [icon(doc, iconName), el(doc, "span", { text })]);
    const op = (t) => el(doc, "span", { className: "pv-onb-sum-op", "aria-hidden": "true", text: t });
    return [
      el(doc, "div", { className: "pv-onb-compare" }, [
        card(`pv-onb-compare-wallet ${seq(0)}`, "key", "Wallet", wWho, wQ, "It answers with a signature — nothing more."),
        card(`pv-onb-compare-pv ${seq(1)}`, "shield", "PolicyVault", pWho, pQ, "Decided deterministically from the vault's policy and its exact live state.")
      ]),
      el(doc, "div", { className: "pv-onb-sum" }, [
        tile(0, "shield", "PolicyVault policy"),
        op("+"),
        tile(1, "wallet", "external signer"),
        op("+"),
        tile(2, "contract", "Kaspa covenant enforcement"),
        op("="),
        el(doc, "span", { className: `pv-onb-sum-tile result ${seq(3)}`, text: "bounded, non-custodial delegated spending" })
      ])
    ];
  }

  const FIGURES = Object.freeze({
    flow: {
      label:
        "How a request travels: AI / App requests a spend; PolicyVault decides whether it is authorized; the authorized transaction reaches the covenant, which enforces the rules on-chain; Kaspa consensus rejects anything outside them.",
      build: buildFlow
    },
    create: {
      label: "The owner's wallet creates, reviews and signs; the vault is a covenant-locked output on Kaspa L1; keys, signing and custody stay in the wallet, PolicyVault prepares and verifies and never signs.",
      build: buildCreate
    },
    rules: {
      label: `Illustrative rules: per spend at most ${EXAMPLE.capKas} KAS; daily budget at most ${EXAMPLE.dailyKas} KAS; approved recipients only; approval above ${EXAMPLE.approvalAboveKas} KAS by ${EXAMPLE.approversRequired} of ${EXAMPLE.approversTotal} approvers.`,
      build: buildRules
    },
    delegate: {
      label: "The owner delegates bounded authority to an agent inside a policy envelope: the agent may request or spend within policy; it may not exceed the cap or budget, expand the policy, or obtain owner custody.",
      build: buildDelegate
    },
    examples: {
      label: `Four requests against the illustrative vault: 2 KAS to A accepted; 8 KAS to A refused for exceeding the ${EXAMPLE.capKas} KAS cap; 1 KAS to an unlisted address refused; 4 KAS to B needs approval.`,
      build: buildExamples
    },
    distinction: {
      label: "A wallet asks whether a key can sign; PolicyVault asks whether an action is authorized. PolicyVault policy plus an external signer plus Kaspa covenant enforcement equals bounded, non-custodial delegated spending.",
      build: buildDistinction
    }
  });

  function renderCore(doc) {
    return el(
      doc,
      "div",
      { className: "pv-onb-core", role: "note" },
      CORE_MESSAGE.map((line, i) => el(doc, "div", { className: `pv-onb-core-line ${seq(i)}`, text: line }))
    );
  }

  function renderBlock(doc, b) {
    switch (b.type) {
      case "art": {
        const f = FIGURES[b.kind];
        return f ? figure(doc, b.kind, f.label, f.build) : null;
      }
      case "core":
        return renderCore(doc);
      case "p":
        return el(doc, "p", { className: "pv-onb-p", text: b.text });
      case "note":
        return el(doc, "p", { className: "pv-onb-note", text: b.text });
      case "ul":
        return el(doc, "ul", { className: "pv-onb-ul" }, b.items.map((t) => el(doc, "li", { text: t })));
      case "docs":
        return el(doc, "p", { className: "pv-onb-p" }, [docsLink(doc, b.slug, b.label)]);
      default:
        return null; // unknown block: render nothing rather than guess
    }
  }

  /* ---------------- controller ---------------- */

  function create(deps) {
    const win = deps.window;
    const doc = deps.document || win.document;
    const storage = storageOf(win);
    // The current content version. Overridable ONLY so tests can prove the
    // cross-version rules (a bump re-shows once; "Don't show again" outlives
    // bumps); the browser always runs ONBOARDING_VERSION.
    const version = Number.isInteger(deps.onboardingVersion) && deps.onboardingVersion >= 1 ? deps.onboardingVersion : ONBOARDING_VERSION;
    const focusableSelector = "button, a[href], input, select, textarea, [tabindex]";

    const state = { open: false, step: 0, reason: null, mounted: false, opener: null, keyHandler: null };
    let card = null;
    let regions = null; // { progress, title, lead, body, dots, back, next, skip, dsa }

    const $ = (id) => doc.getElementById(id);

    function readRecord() {
      const r = storage.read();
      return { available: r.available, record: parseRecord(r.raw) };
    }

    function writeRecord(patch) {
      const { record } = readRecord();
      const next = {
        onboardingVersion: version,
        completed: record ? record.completed : false,
        dontShowAgain: record ? record.dontShowAgain : false,
        ...patch
      };
      return storage.write(next);
    }

    /* Auto-show on first run only: never when storage is unavailable
     * (cannot remember = would nag), never after "Don't show again", and
     * never again once this onboarding version has been shown. */
    function shouldAutoShow() {
      const { available, record } = readRecord();
      if (!available) return false;
      if (!record) return true;
      if (record.dontShowAgain) return false;
      return record.onboardingVersion < version;
    }

    function focusables() {
      if (!card) return [];
      const list = Array.from(card.querySelectorAll(focusableSelector));
      return list.filter((n) => !n.disabled && n.getAttribute("tabindex") !== "-1" && !n.hidden);
    }

    function buildCard() {
      const container = $("pv-onboarding");
      if (!container) return null;
      container.textContent = "";
      const progress = el(doc, "span", { className: "pv-onb-progress", "aria-live": "polite" });
      const close = el(doc, "button", { className: "pv-onb-close", type: "button", "aria-label": "Close walkthrough", text: "✕" });
      const title = el(doc, "h3", { id: "pv-onb-title", className: "pv-onb-title", tabindex: "-1" });
      const lead = el(doc, "p", { id: "pv-onb-lead", className: "pv-onb-lead" });
      const body = el(doc, "div", { className: "pv-onb-body" });
      const dots = el(doc, "div", { className: "pv-onb-dots", "aria-hidden": "true" });
      const skip = el(doc, "button", { className: "pv-onb-skip", type: "button", text: "Skip" });
      const dsaInput = el(doc, "input", { type: "checkbox", id: "pv-onb-dsa" });
      const dsa = el(doc, "label", { className: "pv-onb-dsa", for: "pv-onb-dsa" }, [dsaInput, el(doc, "span", { text: " Don't show this again" })]);
      const back = el(doc, "button", { className: "pv-onb-back", type: "button", text: "Back" });
      const next = el(doc, "button", { className: "pv-onb-next primary", type: "button", text: "Next" });
      card = el(doc, "div", { className: "pv-onb-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "pv-onb-title", "aria-describedby": "pv-onb-lead" }, [
        el(doc, "div", { className: "pv-onb-top" }, [el(doc, "span", { className: "pv-onb-kicker", text: "How PolicyVault works" }), progress, close]),
        title,
        lead,
        body,
        dots,
        el(doc, "div", { className: "pv-onb-foot" }, [skip, dsa, el(doc, "span", { className: "pv-onb-spacer" }), back, next])
      ]);
      container.appendChild(card);
      regions = { progress, title, lead, body, dots, back, next, skip, dsaInput };

      close.addEventListener("click", () => close_("close"));
      skip.addEventListener("click", () => close_("skip"));
      back.addEventListener("click", () => goTo(state.step - 1));
      next.addEventListener("click", () => (state.step >= STEPS.length - 1 ? finish() : goTo(state.step + 1)));
      dsaInput.addEventListener("change", () => writeRecord({ dontShowAgain: !!dsaInput.checked }));
      // Backdrop click (outside the card) closes; clicks inside do not bubble out as a close.
      container.addEventListener("click", (ev) => {
        if (ev && ev.target === container) close_("backdrop");
      });
      return container;
    }

    function paintStep() {
      if (!regions) return;
      const s = STEPS[state.step];
      const n = STEPS.length;
      regions.progress.textContent = `Step ${state.step + 1} of ${n}`;
      regions.title.textContent = s.title;
      regions.lead.textContent = s.lead;
      regions.body.textContent = "";
      regions.body.setAttribute("data-step", s.id);
      for (const b of s.blocks) {
        const node = renderBlock(doc, b);
        if (node) regions.body.appendChild(node);
      }
      regions.dots.textContent = "";
      for (let i = 0; i < n; i++) regions.dots.appendChild(el(doc, "span", { className: "pv-onb-dot" + (i === state.step ? " active" : i < state.step ? " done" : "") }));
      regions.back.disabled = state.step === 0;
      regions.next.textContent = state.step >= n - 1 ? "Finish" : "Next";
      regions.skip.hidden = false; // Skip is visible on every step, including step 1
      const { record } = readRecord();
      regions.dsaInput.checked = !!(record && record.dontShowAgain);
      try {
        if (typeof card.scrollTo === "function") card.scrollTo(0, 0);
      } catch (_) {
        /* scrolling is a courtesy */
      }
      try {
        regions.title.focus();
      } catch (_) {
        /* focus is a courtesy, never a requirement */
      }
    }

    function onKeydown(ev) {
      if (!state.open) return;
      const key = ev.key;
      if (key === "Escape" || key === "Esc") {
        if (ev.preventDefault) ev.preventDefault();
        close_("escape");
        return;
      }
      if (key === "Tab") {
        const list = focusables();
        if (!list.length) return;
        const first = list[0];
        const last = list[list.length - 1];
        const active = doc.activeElement;
        if (ev.shiftKey && (active === first || !card.contains(active))) {
          if (ev.preventDefault) ev.preventDefault();
          last.focus();
        } else if (!ev.shiftKey && (active === last || !card.contains(active))) {
          if (ev.preventDefault) ev.preventDefault();
          first.focus();
        }
      }
    }

    function open(opts) {
      const reason = (opts && opts.reason) || "replay";
      const container = card ? $("pv-onboarding") : buildCard();
      if (!container) return false;
      state.open = true;
      state.reason = reason;
      state.step = 0;
      state.opener = doc.activeElement || null;
      container.hidden = false;
      container.setAttribute("data-reason", reason);
      if (!state.keyHandler) {
        state.keyHandler = onKeydown;
        doc.addEventListener("keydown", state.keyHandler);
      }
      if (reason === "first-run") writeRecord({}); // seen for this version (completed stays false until Finish)
      paintStep();
      return true;
    }

    function close_(how) {
      if (!state.open) return;
      const container = $("pv-onboarding");
      state.open = false;
      if (container) {
        container.hidden = true;
        container.removeAttribute("data-reason");
      }
      if (state.keyHandler) {
        doc.removeEventListener("keydown", state.keyHandler);
        state.keyHandler = null;
      }
      state.lastClose = how;
      const opener = state.opener;
      state.opener = null;
      try {
        if (opener && typeof opener.focus === "function" && opener !== doc.body) opener.focus();
        else if ($("pv-onb-home-btn")) $("pv-onb-home-btn").focus();
      } catch (_) {
        /* focus restoration is best-effort */
      }
    }

    function goTo(i) {
      if (!state.open) return;
      if (i < 0 || i >= STEPS.length) return;
      state.step = i;
      paintStep();
    }

    function finish() {
      writeRecord({ completed: true });
      close_("finish");
    }

    function replay() {
      return open({ reason: "replay" });
    }

    /* Header Help menu + home entry. Every element is optional: a page (or
     * a test) without them simply gets no wiring. Never throws. */
    function wire() {
      const helpBtn = $("pv-help-btn");
      const menu = $("pv-help-menu");
      const replayBtn = $("pv-help-replay");
      const homeBtn = $("pv-onb-home-btn");
      const setMenu = (openMenu) => {
        if (!menu || !helpBtn) return;
        menu.hidden = !openMenu;
        helpBtn.setAttribute("aria-expanded", openMenu ? "true" : "false");
      };
      if (helpBtn && menu) {
        helpBtn.addEventListener("click", () => setMenu(menu.hidden));
        doc.addEventListener("click", (ev) => {
          if (menu.hidden) return;
          const t = ev && ev.target;
          if (t && (t === helpBtn || helpBtn.contains(t) || menu.contains(t))) return;
          setMenu(false);
        });
        doc.addEventListener("keydown", (ev) => {
          if (!menu.hidden && (ev.key === "Escape" || ev.key === "Esc")) {
            setMenu(false);
            try { helpBtn.focus(); } catch (_) { /* best-effort */ }
          }
        });
      }
      if (replayBtn) replayBtn.addEventListener("click", () => { setMenu(false); replay(); });
      if (homeBtn) homeBtn.addEventListener("click", () => open({ reason: "home" }));
      state.wired = true;
    }

    /* Called by web/app.js once boot() has settled — never before, never
     * awaited. Idempotent. Storage-unavailable or already-seen = no-op. */
    function mountAfterBoot() {
      if (state.mounted) return false;
      state.mounted = true;
      if (!shouldAutoShow()) return false;
      return open({ reason: "first-run" });
    }

    return {
      open,
      close: () => close_("api"),
      next: () => (state.step >= STEPS.length - 1 ? finish() : goTo(state.step + 1)),
      back: () => goTo(state.step - 1),
      goTo,
      finish,
      replay,
      wire,
      mountAfterBoot,
      shouldAutoShow,
      readRecord: () => readRecord().record,
      isOpen: () => state.open,
      step: () => state.step,
      reason: () => state.reason,
      lastClose: () => state.lastClose || null,
      _card: () => card
    };
  }

  const surface = {
    ONBOARDING_VERSION,
    STORAGE_KEY,
    DOCS_BASE,
    CORE_MESSAGE,
    FLOW,
    WALLET_QUESTION,
    POLICYVAULT_QUESTION,
    EXAMPLE,
    RULES,
    AGENT_MAY,
    AGENT_MAY_NOT,
    EXAMPLES,
    FIGURES,
    STEPS,
    parseRecord,
    create
  };

  if (typeof window !== "undefined" && window.document && typeof window.document.createElement === "function") {
    try {
      const ctl = create({ window, document: window.document });
      ctl.wire();
      window.PolicyVaultOnboarding = Object.assign({}, surface, ctl);
    } catch (_) {
      /* presentation only: a wiring failure must never affect the app */
    }
  }
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
