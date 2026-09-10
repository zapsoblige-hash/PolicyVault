"use strict";

/*
 * BROWSER — refusal explanations (web/refusal-explain.js, TRACK 11).
 *
 * Adoption failure this fixes: every refusal reached the user as
 * "<action> rejected: CODE <server message>" — a machine code in a red
 * bar, with no statement of what it means or what to do next. Users who
 * hit NOT_OWNER, RECONCILIATION_REQUIRED, INSUFFICIENT_FUEL or
 * CLAIM_CONFLICT had no way to tell a mistake from a bug.
 *
 * The properties these tests pin are the ones that keep an explanation
 * layer SAFE:
 *
 *   1. it is CLOSED — every explained code is one this codebase actually
 *      throws, and an unknown code is NEVER guessed at;
 *   2. the exact code and the server's exact message ALWAYS survive into
 *      the rendering (the explanation is added, never substituted);
 *   3. no entry offers an override / bypass / proceed-anyway;
 *   4. authority language stays truthful: hosted-layer refusals say they
 *      are not covenant-enforced, and vault ownership is described as ONE
 *      on-chain owner key (an organization is metadata);
 *   5. everything is escaped — a server message is untrusted text;
 *   6. app-v4.js routes its money-path refusals through it AND fails
 *      closed to the plain summary when the module is absent.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");
const REPO = path.join(WEB_DIR, "..");
const RX = require("../refusal-explain.js");
const { assertGenerationMainnetCreatable } = require("../../sdk/src/config.js");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
const INDEX_HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");

/* ---------------- 1. the table is closed, and grounded in real codes -------- */

/* Every code in the table must actually appear in the shipped source that
 * can throw it. A table entry for a code nothing emits is dead
 * explanation; worse, it invites inventing codes. */
const SOURCE_HAYSTACK = [
  "server/src/api.js", "server/src/governance.js", "server/src/risk.js", "server/src/auth.js",
  "server/src/agent-suspensions.js", "server/src/organization.js",
  "sdk/src/wallet-requests-v4.js", "sdk/src/wallet-submit-v4.js", "sdk/src/vault-builders-v4.js",
  "sdk/src/approval-package-v4.js", "sdk/src/address-identity.js", "sdk/src/organization.js",
  "sdk/src/config.js", // exact mainnet generation refusal, including legacy BUILD_FAILED wrappers
  "web/app.js", "web/app-v4.js", "web/wallet.js", "web/signer-kasware-adapter.js",
  /* v0.7 organizational M-of-N owner root (Wave 2, Track B-web): the
   * contract's closed refusal vocabulary
   * (docs/postlaunch/v0.7-app-surface-contract.md §2) is thrown or
   * meaningfully mapped-to by web/org-root-ui.js's local fail-closed
   * pre-checks (OWNER_SET_ILL_FORMED, NOT_AN_ACTIVE_SLOT, ROOT_FROZEN,
   * ROOT_PENDING_REQUEST, HOSTED_ORG_IS_NOT_A_ROOT, OWNER_PATH_TAKES_NO_SIGNATURE,
   * UNDER_QUORUM, DUPLICATE_SLOT_SIGNATURE, SLOT_KEY_MISMATCH,
   * RESPONSE_BINDING_MISMATCH) and its exported V7_REFUSAL_CODES closed
   * vocabulary (the two codes with no local pre-check yet —
   * ROOT_STALE_OUTPOINT, DELAY_NOT_ELAPSED — are server/covenant-detected
   * conditions this UI is nonetheless prepared to explain); the rest
   * already exist in the underlying core/sdk modules this UI calls through
   * web/core-bundle.js (owner-set-v7 UNDER_QUORUM/SLOT_KEY_MISMATCH,
   * vault-transitions-v7-root ROOT_FROZEN, vault-builders-v7
   * ROOT_INPUT_REQUIRED/OWNER_PATH_TAKES_NO_SIGNATURE). */
  "web/org-root-ui.js",
  "core/model/owner-set-v7.js", "core/signer/org-root-slot-v7.js",
  "core/model/vault-transitions-v7-root.js", "sdk/src/vault-builders-v7.js",
  /* v0.5/v0.6 TOKEN CONTROLLER and v0.7-payment-hd HIERARCHICAL DELEGATION
   * (Wave 2, Track H-web): the contract's closed §6.1 refusal vocabulary
   * (UNKNOWN_COVENANT_VERSION, VENUE_PROFILE_UNSUPPORTED,
   * ASSET_DESCRIPTOR_INVALID, TOKEN_TEMPLATE_MISMATCH, HD_LEVEL_UNPROVEN,
   * HD_CHAIN_STALE, HD_AUTHORITY_EXCEEDS_ANCESTOR, DELEGATION_WHILE_PAUSED,
   * DELEGATION_WHILE_ROOT_FROZEN) is thrown by web/token-vault-ui.js's and
   * web/hd-vault-ui.js's own local fail-closed pre-checks. */
  "web/token-vault-ui.js", "web/hd-vault-ui.js"
]
  .filter((f) => fs.existsSync(path.join(REPO, f)))
  .map((f) => fs.readFileSync(path.join(REPO, f), "utf8"))
  .join("\n");

test("every explained code is a code this codebase actually emits (no invented codes)", () => {
  const missing = RX.codes().filter((c) => !SOURCE_HAYSTACK.includes(c));
  assert.deepEqual(missing, [], `explanation table contains codes no source emits: ${missing.join(", ")}`);
});

test("an unknown code gets NO explanation — explain() returns null and never guesses", () => {
  assert.equal(RX.explain("TOTALLY_MADE_UP_CODE"), null);
  assert.equal(RX.explain(""), null);
  assert.equal(RX.explain(undefined), null);
  assert.equal(RX.explain(null), null);
  // prototype keys must not leak through as "explanations"
  assert.equal(RX.explain("constructor"), null);
  assert.equal(RX.explain("toString"), null);
  assert.equal(RX.explain("__proto__"), null);
});

test("an unexplained refusal renders the server's message VERBATIM and says so", () => {
  const html = RX.renderRefusalHtml({ summary: "spend rejected: WEIRD_CODE the node said no", code: "WEIRD_CODE", message: "the node said no" });
  assert.match(html, /data-refusal="unexplained"/);
  assert.match(html, /WEIRD_CODE/);
  assert.match(html, /the node said no/);
  assert.match(html, /no closed explanation for this refusal code/);
  // it must not borrow another entry's words
  assert.ok(!/not the vault owner/.test(html));
});

function mainnetGenerationError(version = "policyvault-0.7-payment") {
  try {
    assertGenerationMainnetCreatable({ networkId: "mainnet" }, version);
  } catch (error) {
    assert.equal(error.code, "GENERATION_NOT_MAINNET_AUTHORIZED");
    return error;
  }
  assert.fail(`expected ${version} to be refused on mainnet`);
}

test("the generation refusal explains release availability without blaming address or amounts", () => {
  const error = mainnetGenerationError();
  const explanation = RX.explain(error.code);
  assert.match(explanation.title, /unavailable on mainnet in this release/);
  assert.match(explanation.meaning, /Changing the address or amounts will not enable it/);
  assert.match(explanation.next.join(" "), /single-owner vault.*Create Vault.*v0\.4\.1/);
  assert.doesNotMatch([explanation.meaning, ...explanation.next].join(" "), /nothing was|nothing (?:is |has )?(?:signed|sent|moved)|no transaction was|vault is unchanged|testnet|authorize|override|bypass/i);
});

test("legacy BUILD_FAILED wrappers get the specific explanation only for the exact known SDK guard", () => {
  for (const version of ["policyvault-0.4", "policyvault-0.5", "policyvault-0.6", "policyvault-0.7-root", "policyvault-0.7-payment", "policyvault-0.7-kas", "policyvault-0.7-payment-hd"]) {
    const message = `wallet-requests-v7: ${mainnetGenerationError(version).message}`;
    assert.equal(RX.explain("BUILD_FAILED", message), RX.explain("GENERATION_NOT_MAINNET_AUTHORIZED"));
    const html = RX.renderRefusalHtml({ summary: "Create refused", code: "BUILD_FAILED", message });
    assert.match(html, /data-refusal="BUILD_FAILED"/);
    assert.match(html, /unavailable on mainnet in this release/);
    assert.ok(html.includes(message.replace(/"/g, "&quot;")), "the complete raw SDK message remains visible, escaped");
    assert.doesNotMatch(html, /Adjust the request to fit the policy/);
  }
});

test("unrelated or merely similar BUILD_FAILED messages keep their existing explanation", () => {
  const exact = mainnetGenerationError().message;
  const generic = RX.explain("BUILD_FAILED");
  for (const message of [
    undefined, null, {}, "maximum per payment exceeded", "policyvault-0.7-payment requires a valid address",
    exact.replace("NOT owner-authorized", "owner-authorized"),
    exact.replace("mainnet: covenant", "testnet: covenant"),
    exact.replace(" — refusing (fail closed).", "."),
    exact.replace("policyvault-0.7-payment", "policyvault-0.4.1"),
    exact.replace("policyvault-0.7-payment", "policyvault-future")
  ]) {
    assert.equal(RX.explain("BUILD_FAILED", message), generic);
  }
  assert.equal(RX.explain("UNKNOWN_CODE", exact), null, "message text cannot classify an unknown code");
  assert.equal(RX.explain("NOT_OWNER", exact), RX.explain("NOT_OWNER"), "message text cannot replace a different known code");
});

/* ---------------- 2. code + message always survive ------------------------- */

test("every explained code still renders its exact code and the server's exact message", () => {
  for (const code of RX.codes()) {
    const html = RX.renderRefusalHtml({ summary: "x", code, message: "SERVER-DETAIL-9174" });
    assert.match(html, new RegExp(code), `${code}: the code itself must stay visible`);
    assert.match(html, /SERVER-DETAIL-9174/, `${code}: the server's message must stay visible`);
    const e = RX.explain(code);
    assert.ok(e.title && e.meaning && Array.isArray(e.next) && e.next.length, `${code}: needs a title, a meaning, and at least one next step`);
  }
});

/* ---------------- 3. no override is ever offered --------------------------- */

test("no entry offers an override, a bypass, or a proceed-anyway", () => {
  const forbidden = /(proceed anyway|proceed-anyway|ignore (this|the) (refusal|warning|check)|override|bypass|force (it|the )|disable (the )?(check|verification)|sign it anyway)/i;
  for (const code of RX.codes()) {
    const e = RX.explain(code);
    const text = [e.title, e.meaning, ...e.next].join(" ");
    // The only lawful uses are DENIALS: "there is no proceed-anyway path",
    // "there is no override in this UI".
    const offending = text.match(forbidden);
    if (offending) {
      assert.match(text, /(no proceed-anyway path|no override in this UI)/i, `${code}: "${offending[0]}" must only appear as a denial of one`);
    }
  }
});

test("the browser-verification refusals say DO NOT SIGN and offer no way through", () => {
  for (const code of ["VERIFICATION_REQUIRED", "VERIFICATION_REFUSED", "VERIFICATION_TX_BINDING_MISMATCH"]) {
    const e = RX.explain(code);
    assert.match(e.title, /DO NOT SIGN/, `${code} must say DO NOT SIGN`);
  }
  assert.match(RX.explain("VERIFICATION_REQUIRED").next.join(" "), /no proceed-anyway path/i);
});

/* ---------------- 4. truthful authority language --------------------------- */

test("hosted-layer refusals state that they are NOT covenant-enforced", () => {
  const hosted = ["AGENT_SUSPENDED_HOSTED", "GOVERNANCE_PROPOSAL_REQUIRED", "RISK_REVIEW_REQUIRED", "RISK_DENIED"];
  for (const code of hosted) {
    const e = RX.explain(code);
    assert.match(`${e.meaning} ${e.next.join(" ")}`, /not (a )?covenant|NOT enforced by the covenant|above the covenant/i, `${code} must not be mistaken for covenant enforcement`);
  }
});

test("AGENT_SUSPENDED_HOSTED states what a hosted suspension cannot do, and names the covenant controls", () => {
  const e = RX.explain("AGENT_SUSPENDED_HOSTED");
  assert.match(e.meaning, /cannot stop a holder of the agent key submitting transactions directly to a Kaspa node/i);
  assert.match(e.next.join(" "), /Pause.*Remove agent.*Close & recover/);
});

test("NOT_OWNER describes ONE on-chain owner key and denies organizations any owner authority", () => {
  const e = RX.explain("NOT_OWNER");
  assert.match(e.meaning, /exactly ONE on-chain owner key/);
  assert.match(e.meaning, /organizations[^.]*metadata[^.]*grant no owner authority/i);
});

test("UNKNOWN_APPROVER separates an organization \"approver\" label from a covenant approver", () => {
  const e = RX.explain("UNKNOWN_APPROVER");
  assert.match(e.meaning, /organization role labelled "approver"[^.]*is NOT a covenant approver/i);
});

test("INSUFFICIENT_APPROVALS says the covenant enforces it and the server cannot waive it", () => {
  const e = RX.explain("INSUFFICIENT_APPROVALS");
  assert.match(e.meaning, /covenant enforces this — the server cannot waive it/);
});

/* ---------------- 5. escaping ---------------------------------------------- */

/* The strongest form of this assertion: the ONLY "<" characters in the
 * output are the module's own literal tags. Any other one would mean a
 * server-supplied string reached the DOM as markup. */
const ALLOWED_TAGS = /^\/?(div|b|span|ul|li)[ >]/;
function unexpectedTags(html) {
  const out = [];
  for (let i = html.indexOf("<"); i >= 0; i = html.indexOf("<", i + 1)) {
    const rest = html.slice(i + 1, i + 12);
    if (!ALLOWED_TAGS.test(rest)) out.push(html.slice(i, i + 40));
  }
  return out;
}

test("a hostile server message or code cannot inject markup", () => {
  const html = RX.renderRefusalHtml({
    summary: "<img src=x onerror=alert(1)>",
    code: "<script>alert(2)</script>",
    message: '"><script>alert(3)</script>'
  });
  assert.deepEqual(unexpectedTags(html), [], "every < in the output is one of the module's own literal tags");
  assert.ok(!/<script/i.test(html), "no script tag survives");
  assert.ok(!/<img/i.test(html), "no img tag survives");
  assert.match(html, /&lt;script&gt;/, "the hostile text is shown, escaped, not dropped");
});

test("an explained code with hostile text in the server message is equally safe", () => {
  const html = RX.renderRefusalHtml({ summary: "s", code: "NOT_OWNER", message: '</div><img src=x onerror="alert(1)">' });
  assert.deepEqual(unexpectedTags(html), []);
  assert.match(html, /&lt;img/);
});

test("generation explanations preserve and escape hostile text, including a legacy wrapper", () => {
  const message = `${mainnetGenerationError().message} </div><img src=x onerror="alert(1)"> & detail`;
  for (const code of ["GENERATION_NOT_MAINNET_AUTHORIZED", "BUILD_FAILED"]) {
    const html = RX.renderRefusalHtml({ summary: "<script>summary</script>", code, message });
    assert.match(html, /unavailable on mainnet in this release/);
    assert.deepEqual(unexpectedTags(html), []);
    assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt; &amp; detail/);
    assert.ok(html.includes(`<span class="mono">${code}</span>`), "the original error code survives");
  }
});

test("an explained refusal's own text is escaped into the attribute too", () => {
  const html = RX.renderRefusalHtml({ summary: "s", code: 'X"><b>', message: "m" });
  assert.ok(!/data-refusal="X"><b>"/.test(html));
  assert.match(html, /data-refusal="unexplained"/);
});

/* ---------------- 6. wiring + fail-closed degradation ---------------------- */

test("index.html loads refusal-explain.js before app-v4.js consumes it", () => {
  const iRefusal = INDEX_HTML.indexOf('src="/refusal-explain.js"');
  const iAppV4 = INDEX_HTML.indexOf('src="/app-v4.js"');
  assert.ok(iRefusal > 0, "refusal-explain.js is loaded");
  assert.ok(iRefusal < iAppV4, "it loads before app-v4.js");
});

test("app-v4.js routes its money-path refusals through noteRefusal", () => {
  assert.match(APP_V4, /function noteRefusal\(prefix, e\)/);
  for (const site of [
    'noteRefusal(`${action} rejected`, e)',
    'noteRefusal(`${action} failed`, e)',
    /* STALE ASSUMPTION (2026-09-05, guided setup): the create flow's two
     * refusal sites are now "Create refused" (server build refusal, draft
     * kept) and "Signing did not complete — nothing was sent" (wallet
     * rejection / disconnect, recoverable state) — still noteRefusal. */
    'noteRefusal("Create refused", err)',
    'noteRefusal("Signing did not complete — nothing was sent", err)',
    'noteRefusal("Submission outcome uncertain — do not sign again", err)' // UX-05: the uncertain-outcome site now blocks re-signing until reconciled
  ]) {
    assert.ok(APP_V4.includes(site), `missing refusal wiring: ${site}`);
  }
  // the old bare-code rendering must be gone from those paths
  assert.ok(!/note\(`\$\{action\} rejected: /.test(APP_V4));
  assert.ok(!/note\(`Create rejected: /.test(APP_V4));
});

test("noteRefusal writes the plain summary FIRST, so a page without the module still shows the refusal", () => {
  const fn = /function noteRefusal\(prefix, e\) \{[\s\S]*?\n  \}/.exec(APP_V4)[0];
  const iSummary = fn.indexOf('note(summary, "bad")');
  const iModule = fn.indexOf("refusalExplain()");
  assert.ok(iSummary > 0 && iSummary < iModule, "the refusal is displayed before the module is even consulted");
  assert.match(fn, /if \(!mod \|\| !el\) return;/, "an absent module is a no-op, not a crash");
  assert.match(fn, /catch \{/, "an explanation defect can never hide the refusal");
});

test("noteRefusal keeps the code and the message in the summary line itself", () => {
  const fn = /function noteRefusal\(prefix, e\) \{[\s\S]*?\n  \}/.exec(APP_V4)[0];
  assert.match(fn, /const summary = `\$\{prefix\}: \$\{code\} \$\{message\}`/);
});

/* ======================================================================= *
 * OUTCOMES — PENDING IS NOT SUCCESS                                       *
 * ======================================================================= */

/* The v0.4.1 durable request states, read from the SDK's own state machine
 * so the table can never drift into describing states that do not exist,
 * or miss ones that do. */
const REQUEST_STATE_SRC = fs.readFileSync(path.join(REPO, "sdk/src/wallet-requests-v4.js"), "utf8");
const SDK_STATES = (() => {
  const block = /const RequestState = Object\.freeze\(\{([\s\S]*?)\n\}\);/.exec(REQUEST_STATE_SRC);
  assert.ok(block, "found the SDK RequestState enum");
  return [...block[1].matchAll(/^\s*([A-Z_]+):\s*"([A-Z_]+)"/gm)].map((m) => m[2]);
})();

/* The fail-closed states (WALLET_REJECTED, STALE, BUILD_FAILED, …) reach
 * the user through the REFUSAL path, not the outcome path. */
const REFUSAL_STATES = new Set([
  "WALLET_REJECTED", "SIGNATURE_INVALID", "PREFLIGHT_FAILED", "STALE",
  "CLAIM_CONFLICT", "AUTHORIZATION_FAILED", "INSUFFICIENT_APPROVALS", "BUILD_FAILED"
]);

test("the outcome table describes only real SDK request states", () => {
  const invented = RX.outcomeStates().filter((s) => !SDK_STATES.includes(s));
  assert.deepEqual(invented, [], `outcome table names states the SDK does not define: ${invented.join(", ")}`);
});

test("every non-refusal SDK request state has a closed outcome description", () => {
  const missing = SDK_STATES.filter((s) => !REFUSAL_STATES.has(s) && !RX.outcomeStates().includes(s));
  assert.deepEqual(missing, [], `pipeline states with no description: ${missing.join(", ")}`);
});

test("EXACTLY ONE state is success: CHAIN_VERIFIED", () => {
  const verified = RX.outcomeStates().filter((s) => RX.outcome(s).level === "verified");
  assert.deepEqual(verified, ["CHAIN_VERIFIED"]);
  assert.equal(RX.isVerifiedOutcome("CHAIN_VERIFIED"), true);
  for (const s of SDK_STATES.filter((x) => x !== "CHAIN_VERIFIED")) {
    assert.equal(RX.isVerifiedOutcome(s), false, `${s} must never count as success`);
  }
});

test("an UNKNOWN request state fails closed to pending — never success", () => {
  for (const s of ["SOMETHING_NEW", "", null, undefined, "constructor", "__proto__"]) {
    assert.equal(RX.isVerifiedOutcome(s), false, `${String(s)} must not be success`);
    assert.equal(RX.outcome(s).level, "pending", `${String(s)} must be treated as unconfirmed`);
  }
  assert.match(RX.outcome("SOMETHING_NEW").meaning, /no closed description|NOT a completed transaction/i);
});

test("SUBMITTED is explicitly not a confirmation, and says what to do", () => {
  const o = RX.outcome("SUBMITTED");
  assert.equal(o.level, "pending");
  assert.match(o.title, /NOT yet confirmed/i);
  assert.match(o.meaning, /not proof it is in the DAG/i);
  assert.match(o.next.join(" "), /Verify state/);
});

test("CHAIN_VERIFIED is the only description that claims proof; every other one denies it", () => {
  assert.match(RX.outcome("CHAIN_VERIFIED").meaning, /only outcome that is proven/i);
  // Wherever a non-verified description mentions proof/confirmation at all,
  // it must be a DENIAL — never an affirmation.
  const DENIAL = /(not proof|not (yet )?(proven|confirmed)|nothing (is|has|have)|no closed description|could not|is not on the chain|NOT a completed|may or may not|may still be confirmed, or it may not)/i;
  for (const s of RX.outcomeStates()) {
    const o = RX.outcome(s);
    if (o.level === "verified") continue;
    const text = `${o.title} ${o.meaning}`;
    assert.ok(!/only outcome that is proven|is proven|has been confirmed|is confirmed\b/i.test(text), `${s}: must not claim proof`);
    if (/prov(en|f)|confirm/i.test(text)) {
      assert.match(text, DENIAL, `${s}: any mention of proof/confirmation must be a denial`);
    }
  }
  // And the same for UNKNOWN_OUTCOME.
  assert.ok(!/is proven|is confirmed\b/i.test(RX.outcome("SOMETHING_NEW").meaning));
});

test("the outcome rendering always keeps the raw state name and the FULL txid", () => {
  const txid = "ab".repeat(32);
  const html = RX.renderOutcomeHtml({ summary: "s", state: "SUBMITTED", txId: txid });
  assert.match(html, /SUBMITTED/);
  assert.match(html, new RegExp(txid), "the txid is shown in full, never truncated, so it can be looked up");
  assert.match(html, /data-outcome-level="pending"/);
});

test("outcome rendering escapes a hostile state name / txid", () => {
  const html = RX.renderOutcomeHtml({ summary: "s", state: '"><script>x</script>', txId: "<img src=x>" });
  assert.deepEqual(unexpectedTags(html), []);
  assert.match(html, /data-outcome-level="pending"/, "an unrecognised state is pending, not success");
});

test("app-v4.js routes every completed-flow outcome through noteOutcome", () => {
  assert.match(APP_V4, /function noteOutcome\(prefix, state, txId, detail\)/);
  assert.ok(APP_V4.includes("noteOutcome(action, sub.request.state, sub.txId, sub.request.error)"), "submit outcome");
  assert.ok(APP_V4.includes("noteOutcome(action, done.request.state, null, done.request.error)"), "non-preflight outcome");
  assert.ok(APP_V4.includes('noteOutcome("Create vault", done.request.state, done.txId, done.request.error)'), "genesis outcome");
  // the old inline "is it CHAIN_VERIFIED" string building must be gone
  assert.ok(!/\(relayed \+ chain-verified\)"\}`, ok \? "good"/.test(APP_V4));
});

test("noteOutcome grants the success class only to a verified outcome, and says NOT YET CONFIRMED otherwise", () => {
  const fn = /function noteOutcome\(prefix, state, txId, detail\) \{[\s\S]*?\n  \}/.exec(APP_V4)[0];
  assert.match(fn, /NOT YET CONFIRMED/);
  assert.match(fn, /note\(summary, verified \? "good" : "warn"\)/);
  assert.match(fn, /isVerifiedOutcome/, "the module decides, so an unrecognised state cannot become success");
  assert.match(fn, /state === "CHAIN_VERIFIED"/, "and the module-absent fallback is still the strict comparison");
});
