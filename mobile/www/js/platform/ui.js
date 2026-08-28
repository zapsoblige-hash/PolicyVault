"use strict";

/*
 * PolicyVault mobile — PLATFORM LAYER: DOM rendering helpers, including
 * the PASS / DO-NOT-SIGN ceremony.
 *
 * The verdict renderer here displays `outcome.lines` — the array the
 * PACKAGED verifier produced, via core/explain — verbatim and in order.
 * It composes no sentence of its own about what a transaction does. That
 * is the whole point: there is exactly ONE implementation of the text a
 * human reads before authorizing money to move, and it is the reviewed
 * one (mobile-architecture-decision.md §3.2 point 3, §6.3).
 *
 * MOBILE-SPECIFIC HAZARD RULES IMPLEMENTED HERE (§6.3):
 *
 *   1. THE REFUSAL OWNS THE SCREEN. A refusal renders as a full-screen,
 *      opaque interstitial — never a toast, banner, collapsible section,
 *      or draggable bottom sheet.
 *   2. THE SIGNING AFFORDANCE IS ABSENT, NOT DISABLED. On a refusal this
 *      renderer emits no signing control at all. There is no greyed
 *      button, no long-press override, no "I understand the risks".
 *   4. CODES VERBATIM + PLAIN LANGUAGE, in a copyable diagnostics block.
 *   7. NOT COLOUR ALONE — icon + heading text + colour.
 *   8. NO TRUNCATION OF VALUE-BEARING TEXT, EVER. Every line is rendered
 *      with `overflow-wrap: anywhere` and no ellipsis. The CSS carries no
 *      `text-overflow: ellipsis` for these elements, and the test suite
 *      asserts that no ellipsis character reaches the DOM. Eliding an
 *      address or an amount is the most likely way a small screen
 *      silently weakens this ceremony.
 *
 * Rules 3 (independent second refusal), 6 (navigation cannot become
 * consent), 9 (FLAG_SECURE) and 10 (no deep link lands on a signing
 * action) are NOT this file's job: 3 lives in the portable layer
 * (airgap.authorizeSigning), and 6/9/10 need native integrations this
 * scaffold does not have. They are recorded as unverified in
 * docs/postlaunch/mobile-v1-scaffold.md.
 */

(function (globalScope) {
  function esc(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = attrs[k];
        else if (k === "onclick") node.addEventListener("click", attrs[k]);
        else node.setAttribute(k, attrs[k]);
      }
    }
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  /* A block of untruncated, wrapping, monospaced text. Used for every
   * value-bearing string: addresses, public keys, amounts, digests,
   * payloads. */
  function full(textContent, extraClass) {
    return el("div", { class: "fullvalue " + (extraClass || ""), text: String(textContent) });
  }

  function kv(label, value) {
    return el("div", { class: "kv" }, [
      el("div", { class: "k", text: label }),
      full(value, "v")
    ]);
  }

  function note(text, kind) {
    return el("div", { class: "note " + (kind || ""), text: text });
  }

  /*
   * A label for something the build cannot do. Fail-closed UX: the reason
   * is always stated, and no control is offered next to it.
   */
  function unavailable(what, reason) {
    return el("div", { class: "unavailable" }, [
      el("div", { class: "unavailable-head", text: "UNAVAILABLE — " + what }),
      el("div", { class: "unavailable-why", text: reason })
    ]);
  }

  /**
   * renderVerdict(outcome) -> HTMLElement
   *
   * `outcome` is exactly what the portable verification module returned.
   * A missing/malformed outcome renders as a refusal, never as neutral
   * (§6.3 rule 5: a verification error IS a refusal).
   */
  function renderVerdict(outcome) {
    var isPass = Boolean(outcome && outcome.ok === true && outcome.verdict === "VERIFIED_EXACT");
    var lines = outcome && Array.isArray(outcome.lines) && outcome.lines.length
      ? outcome.lines
      : ["!! DO NOT SIGN !!", "NO VERIFICATION OUTCOME was produced for this transaction.", "Refusal codes: VERIFICATION_REQUIRED."];

    var wrap = el("div", { class: isPass ? "verdict pass" : "verdict refuse" });

    /* Rule 7: icon + heading text + colour, never colour alone. */
    wrap.appendChild(el("div", { class: "verdict-head" }, [
      el("span", { class: "verdict-icon", "aria-hidden": "true", text: isPass ? "✓" : "⚠" }),
      el("span", { class: "verdict-title", text: isPass ? "VERIFIED ON THIS DEVICE" : "DO NOT SIGN" })
    ]));

    /* Rule 8: every line in full, wrapped, never truncated. */
    var body = el("div", { class: "verdict-lines" });
    lines.forEach(function (line) { body.appendChild(full(line, "line")); });
    wrap.appendChild(body);

    if (!isPass) {
      var codes = (outcome && Array.isArray(outcome.refusalCodes) ? outcome.refusalCodes : ["VERIFICATION_REQUIRED"]);
      wrap.appendChild(el("div", { class: "diag" }, [
        el("div", { class: "diag-head", text: "Diagnostics (copy this for support — it contains no vault contents)" }),
        full(codes.join(", "), "diag-codes")
      ]));
      /* Rule 2: NOTHING that could lead to a signature is emitted here. */
      wrap.appendChild(note(
        "There is no proceed-anyway path. Rebuild the request and verify again.",
        "hard"
      ));
    } else if (outcome && Array.isArray(outcome.notes) && outcome.notes.length) {
      var n = el("div", { class: "verdict-notes" });
      outcome.notes.forEach(function (t) { n.appendChild(full(t, "note-line")); });
      wrap.appendChild(n);
    }

    return wrap;
  }

  /**
   * mountRefusalInterstitial(container, outcome)
   *
   * Rule 1: the refusal owns the screen. The interstitial is opaque,
   * fixed, covers the viewport, and is dismissed only by an explicit
   * CANCEL — which resolves to cancel, never to consent.
   */
  function mountRefusalInterstitial(container, outcome, onCancel) {
    var overlay = el("div", { class: "interstitial", role: "alertdialog", "aria-modal": "true" });
    var card = el("div", { class: "interstitial-card" });
    card.appendChild(renderVerdict(outcome));
    card.appendChild(el("button", {
      class: "btn cancel",
      text: "Cancel — nothing was signed",
      onclick: function () {
        overlay.remove();
        if (typeof onCancel === "function") onCancel();
      }
    }));
    overlay.appendChild(card);
    container.appendChild(overlay);
    return overlay;
  }

  var api = {
    esc: esc,
    el: el,
    full: full,
    kv: kv,
    note: note,
    unavailable: unavailable,
    renderVerdict: renderVerdict,
    mountRefusalInterstitial: mountRefusalInterstitial
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileUi = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
