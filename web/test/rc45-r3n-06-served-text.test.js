"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — the SERVED TEXT: the withdrawal wording (owner criterion 5: withdrawing does not
 * revoke the owner signatures or prevent an otherwise valid broadcast outside PolicyVault), the attribution answers,
 * the UNRESOLVED treasury, the SUPERSEDED outcome and the two new refusal explanations. Internal RED-first regression
 * material for the RC45 candidate; not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR (contract revision 2 §1 D8; the RED list legs named in each title):
 *   - withdrawal text S (verbatim): app-v4's stale-withdrawal confirmation keeps its aged-out first sentence, then S;
 *     org-root-ui's stale withdrawal reason keeps its aged-out lead clause, then S; "discards the owner approvals" is
 *     gone; a REFUSED request carrying a signed slot reads "Withdrawn — PolicyVault will not finalize or send it" plus
 *     the non-revocation; no served org-root text says withdrawal discards / revokes approvals or prevents a broadcast
 *     (the deferred v0.4 cancel texts are listed, GAP-15);
 *   - describeReconcileOutcome: ADVANCED via attribution names A, its txid, "broadcast outside PolicyVault" and the
 *     depth; FULL (good) carries the GAP-2b warning with writer amendment A1-6's hold clause (R3N-B1 approved, so the
 *     not-approved "and can hold the root again" is dropped: addendum v2a item 6; R3N-B1a-inventory re-pin); PARTIAL
 *     (warn) states T1 UNRESOLVED, its hosted actions refused and that a root FREEZE does not stop its delegates; the
 *     buildability sentence comes only from `buildable` (root hold -> warn naming it; null -> not determined) and never
 *     lists the UNRESOLVED treasury; never "recovered / restored / complete"; UNKNOWN SUBMIT_TO_RECORD tells the
 *     operator to press Submit on the named request, then Verify state;
 *   - requestOutcome: SUPERSEDED is a closed terminal outcome; CHAIN_VERIFIED with a bound PARTIAL marker is the warn
 *     "Chain-verified root move — treasury UNRESOLVED" (FULL / unmarked unchanged);
 *   - refusal-explain: RECORDED_OUTPUT_SPENT (conditional "build again") and TREASURY_STATE_UNRESOLVED;
 *   - kas-vault-ui: a treasury with stateUnresolved shows the "STATE UNRESOLVED" badge (last-record values).
 *
 * Layer: BROWSER modules (the real web/org-root-ui.js, web/kas-vault-ui.js, web/refusal-explain.js over the real
 * web/core-bundle.js; fixture responses only) plus a served-asset source scan. Labels as in the sdk legs.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");
const REPO = path.join(WEB_DIR, "..");
const core = require("../core-bundle.js");
const setupMod = require("../setup-ui.js");
const orgRootUiMod = require("../org-root-ui.js");
const kasMod = require("../kas-vault-ui.js");
const RX = require("../refusal-explain.js");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
const FX = JSON.parse(fs.readFileSync(path.join(REPO, "core/explain/test/fixtures/v7-kas-manifests.json"), "utf8"));

/* the withdrawal text S of the contract, verbatim */
const S = "Withdrawing marks this request withdrawn in PolicyVault and releases the root's reservation. It does not revoke the owner signatures already given: anyone holding them and the fee-input signature can still broadcast this exact transaction outside PolicyVault while the outputs it spends are unspent. Withdrawing broadcasts nothing.";
/* the TREASURY_STATE_UNRESOLVED explanation, verbatim: binding writer decision 'wording after the PARTIAL upgrade'
 * item 1, which replaces contract D8's "Verify does not resolve it in this release" (RC45 C4-03c) */
const UNRESOLVED_EXPLANATION = "PolicyVault cannot confirm this treasury's current state: its expected output was spent outside PolicyVault after an out-of-band change to its delegate rules. Hosted actions on this treasury stay closed. A later Verify restores them only if it finds that expected output unspent again (for example after a reorganization); otherwise only the owners' direct on-chain exit can act on it.";
const AGED_SENTENCE = "Its delegate budget period start has aged out, so PolicyVault will not finalize it.";
const AGED_LEAD = "its delegate budget period start has aged out, so PolicyVault will not finalize it";
const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const KAS_PROFILE = "policyvault-0.7-kas";
const ROOT_ID = "52".repeat(32), T1 = "44".repeat(32), T2 = "45".repeat(32), X = "ab".repeat(32), A_ID = "q-a-out-of-band";

function fakeApi() {
  return {
    calls: [],
    async getJSON(p) { throw Object.assign(new Error(`no fake response for GET ${p}`), { code: "FAKE_UNMAPPED" }); },
    async postJSON(p) { throw Object.assign(new Error(`no fake response for POST ${p}`), { code: "FAKE_UNMAPPED" }); },
    async resolveXOnly(address) { throw Object.assign(new Error(`address rejected: ${address}`), { code: "ADDRESS_INVALID" }); }
  };
}
function mods() {
  const api = fakeApi();
  const setup = setupMod.createModule({ core });
  const base = orgRootUiMod.createModule({ api, core, setup });
  const km = kasMod.createModule({ api, core, setup, payload: { parseSigningPayload: base.parseSigningPayload, frozenMismatches: base.frozenMismatches } });
  const m = orgRootUiMod.createModule({ api, core, setup, kas: km }); // the root surface with the KAS treasury module loaded (as the app wires it)
  return { m, km };
}
const text = (html) => String(html ?? "").replace(/<[^>]*>/g, " ").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
const NEVER_RECOVERED = /\b(recovered|restored|complete)\b/i;

/* the production-byte KAS delegate-rule change manifest (as the server presents a request) */
const SET = FX.manifests.find((x) => x.name === "vault_owner_set_agent_root");
assert.ok(SET, "fixture vault_owner_set_agent_root");
const ROOT = { rootCovenantId: ROOT_ID, networkId: "testnet-10", state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1" }, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspa:qown1" }, { slot: 2, publicKey: K(0x72), address: "kaspa:qown2" }, { slot: 3, publicKey: K(0x73), address: "kaspa:qown3" }], template: {}, vaults: [T1, T2], pendingRequestId: null, live: { outpoint: { transactionId: X, index: 1 } } };
const kasRuleChange = (over = {}) => ({
  id: A_ID, rootCovenantId: ROOT_ID, kind: "rootAction", action: "authorize", state: "AUTHORIZED", requiredApprovals: "2", signaturesPresent: 2, txId: X,
  slots: [{ slot: 1, publicKey: K(0x71), status: "SIGNED" }, { slot: 2, publicKey: K(0x72), status: "SIGNED" }, { slot: 3, publicKey: K(0x73), status: "PENDING" }],
  vaultOperations: [{ vaultId: T1, profile: KAS_PROFILE, action: "ownerSetAgentRoot", params: { agents: [] }, predecessor: { outpoint: { transactionId: "cd".repeat(32), index: 0 }, generation: 0, latestTransitionTxId: null } }], newRegistry: [],
  manifest: SET.manifest, redeemScripts: SET.redeemScripts, rootInputIndex: SET.rootInputIndex,
  transaction: { unsignedSafeJson: SET.unsignedSafeJson, frozenCanonicalJson: SET.frozenCanonicalJson, signInputs: SET.signInputs }, ...over
});
const marker = (mode) => ({ schema: "policyvault-oob-attribution/1", via: "attribution", txId: X, requestId: A_ID, observedVirtualDaa: "546000000", rootEntryDaa: "545999000", depthDaa: "1000", requiredDepthDaa: "1000", mode, treasury: { vaultId: T1, predecessorOutpoint: { transactionId: "cd".repeat(32), index: 0 }, state: mode === "PARTIAL" ? "UNRESOLVED" : "ADVANCED" }, at: "2000-01-01T00:00:00.000Z" });
const chainVerified = (over = {}) => kasRuleChange({ state: "CHAIN_VERIFIED", chain: { predecessorOutpoint: `${"cc".repeat(32)}:0`, successorOutpoint: `${X}:1` }, ...over });
const detail = (m, request) => text(m.renderRequestDetailHtml(request, { orgRoot: ROOT, viewerXOnly: K(0x73) }));
const advanced = (mode, over = {}) => ({ reconcile: { root: { status: "ADVANCED", rootCovenantId: ROOT_ID, txId: X, requestId: A_ID, via: "attribution", mode, depthDaa: "1000", requiredDepthDaa: "1000", treasury: { vaultId: T1, state: mode === "FULL" ? "ADVANCED" : "UNRESOLVED" }, settled: [], unsettled: [], holds: mode === "FULL" ? [] : [{ scope: T1, reason: "UNRESOLVED", requestId: A_ID, txId: X }], buildable: { root: true, treasuries: mode === "FULL" ? [T1, T2] : [T2] }, ...over }, vaults: [{ vaultId: T1, status: mode === "FULL" ? "CONSISTENT" : "UNKNOWN" }, { vaultId: T2, status: "CONSISTENT" }] } });
/* the sentences of a text that claim buildability */
const buildSentences = (t) => t.split(/(?<=[.!?])\s+/).filter((s) => /built again/i.test(s));

/* ---- app-v4's confirmations as the browser shows them ----
 * Every `window.confirm(<flag> ? … : …)` call of web/app-v4.js is evaluated for <flag> true and false: its string
 * literals decoded (escapes such as \' or ’ included), concatenations joined, and module constants built from
 * string literals resolved. WD-01 therefore reads the rendered text, however the source splits or escapes it. */
const norm = (s) => String(s).replace(/\s+/g, " ").trim();
/* index of the character closing the string / template literal that opens at src[i] */
function literalEnd(src, i) {
  const q = src[i];
  for (let j = i + 1; j < src.length; j++) {
    if (src[j] === "\\") { j += 1; continue; }
    if (src[j] === q) return j;
  }
  throw new Error(`unterminated literal at ${i}`);
}
/* the source text from `start` up to (not including) the first `stop` character at bracket depth 0 */
function exprUntil(src, start, stops) {
  let depth = 0;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") { i = literalEnd(src, i); continue; }
    if (c === "/" && src[i + 1] === "/") { i = src.indexOf("\n", i); if (i < 0) break; continue; }
    if (c === "/" && src[i + 1] === "*") { i = src.indexOf("*/", i + 2) + 1; continue; }
    if ("([{".includes(c)) depth += 1;
    else if (")]}".includes(c)) { if (depth === 0) return src.slice(start, i); depth -= 1; }
    else if (depth === 0 && stops.includes(c)) return src.slice(start, i);
  }
  throw new Error(`unterminated expression at ${start}`);
}
const APP_V4_CONSTANTS = new Map();
/* the value of a module constant of app-v4.js (`const NAME = <string expression>;`), evaluated the same way */
function appV4Constant(name, path) {
  if (APP_V4_CONSTANTS.has(name)) return APP_V4_CONSTANTS.get(name);
  if (path.includes(name)) throw new Error(`cyclic constant ${name}`);
  const decl = new RegExp(`\\b(?:const|let|var)\\s+${name.replace(/\$/g, "\\$")}\\s*=\\s*`).exec(APP_V4);
  if (!decl) throw new Error(`${name} is not a constant of app-v4.js`);
  const value = renderServed(exprUntil(APP_V4, decl.index + decl[0].length, ";,"), {}, [...path, name]);
  APP_V4_CONSTANTS.set(name, value);
  return value;
}
function renderServed(expr, scope, path = []) {
  const vm = require("node:vm");
  const consts = {};
  for (let n = 0; n < 50; n++) {
    try { return vm.runInNewContext(`(${expr})`, { ...consts, ...scope }, { timeout: 1000 }); } catch (e) {
      const m = /^([A-Za-z_$][\w$]*) is not defined$/.exec(String(e && e.message));
      if (!m || (e && e.name) !== "ReferenceError" || Object.prototype.hasOwnProperty.call(consts, m[1])) throw e;
      consts[m[1]] = appV4Constant(m[1], path);
    }
  }
  throw new Error("too many unresolved names");
}
function appV4Confirms() {
  const found = [], errors = [];
  for (const m of APP_V4.matchAll(/window\.confirm\(\s*([A-Za-z_$][\w$]*)\s*\?/g)) {
    try {
      const expr = exprUntil(APP_V4, m.index + "window.confirm(".length, "");
      found.push({ flag: m[1], whenTrue: norm(renderServed(expr, { [m[1]]: true })), whenFalse: norm(renderServed(expr, { [m[1]]: false })) });
    } catch (e) { errors.push(`${m[1]}: ${e.message}`); }
  }
  return { found, errors };
}

/* =============================== WD: the withdrawal wording =============================== */
test("RC45 L2-01: WD-01 app-v4's stale-withdrawal confirmation, as rendered, keeps its aged-out first sentence followed by the withdrawal text S verbatim — withdrawing releases the root's reservation but neither revokes the owner signatures already given nor prevents a broadcast of the transaction outside PolicyVault — and no longer says the owner approvals are discarded [RED on 8877dee]", () => {
  const { found, errors } = appV4Confirms();
  const stale = found.filter((c) => c.whenTrue.includes(AGED_SENTENCE));
  assert.equal(stale.length, 1, `exactly one confirmation carries the aged-out first sentence (found ${stale.length}; not evaluated: ${errors.join("; ") || "none"})`);
  const said = stale[0].whenTrue;
  assert.ok(said.includes(S), `the confirmation states S verbatim — withdrawing does not revoke the owner signatures or prevent a broadcast outside PolicyVault; it says: ${said}`);
  assert.ok(said.indexOf(S) > said.indexOf(AGED_SENTENCE), "S follows the aged-out sentence");
  assert.doesNotMatch(said, /discards the owner approvals/i, "'discards the owner approvals' is removed");
  assert.match(APP_V4, /if \(st === "REFUSED"\) \{ note\("Request withdrawn/, "the success note is unchanged");
});

test("RC45 L2-01: WD-02 org-root-ui's stale withdrawal reason keeps its aged-out lead clause followed by the withdrawal text S verbatim — withdrawing releases the root's reservation but neither revokes the owner signatures already given nor prevents a broadcast of the transaction outside PolicyVault — and no longer says the owner approvals are discarded [RED on 8877dee]", () => {
  const { m } = mods();
  const e = m.withdrawEligibility(kasRuleChange(), { serverRefusedStale: true });
  assert.equal(e.kind, "withdraw", e.reason);
  assert.ok(e.reason.includes(AGED_LEAD), `the aged-out lead clause is kept (${e.reason})`);
  assert.ok(e.reason.includes(S), `S follows it verbatim (${e.reason})`);
  assert.ok(e.reason.indexOf(S) > e.reason.indexOf(AGED_LEAD));
  assert.doesNotMatch(e.reason, /discards the owner approvals/);
});

test("RC45 L2-01: WD-03 a REFUSED request that carries a signed owner slot reads 'Withdrawn — PolicyVault will not finalize or send it' and states both halves of the withdrawal's meaning: the owner signatures already given are not revoked, and the transaction can still be broadcast outside PolicyVault; an unsigned REFUSED request keeps the C3 outcome [RED on 8877dee]", () => {
  const { m } = mods();
  const t = detail(m, kasRuleChange({ state: "REFUSED" }));
  assert.ok(t.includes("Withdrawn — PolicyVault will not finalize or send it"), `the withdrawn title (${t.slice(0, 600)})`);
  assert.match(t, /does not revoke the owner signatures/i, "the non-revocation is stated");
  assert.match(t, /\bcan still\b[^.]{0,160}?\bbroadcast\w*\b[^.]{0,160}?\boutside PolicyVault\b|\bbroadcast\w*\b[^.]{0,160}?\boutside PolicyVault\b[^.]{0,80}?\b(?:remains|stays|is still) possible\b/i, `the broadcast half is stated: the transaction can still be broadcast outside PolicyVault (${t.slice(0, 900)})`);
  assert.doesNotMatch(t, /Refused — nothing happened/, "never the plain refusal for a request carrying signatures");
  const unsigned = detail(m, kasRuleChange({ state: "REFUSED", signaturesPresent: 0, slots: [{ slot: 1, publicKey: K(0x71), status: "PENDING" }, { slot: 2, publicKey: K(0x72), status: "PENDING" }, { slot: 3, publicKey: K(0x73), status: "PENDING" }] }));
  assert.ok(unsigned.includes("Refused — nothing happened"), "an unsigned REFUSED request keeps its outcome");
});

test("RC45 L2-01: WD-05 served-asset scan: no served org-root text says that withdrawing discards or revokes the owner approvals or signatures or prevents a broadcast; the deferred v0.4 cancel texts (GAP-15) are listed exceptions [RED on 8877dee]", () => {
  const assets = fs.readdirSync(WEB_DIR).filter((f) => /\.(js|html)$/.test(f)).sort();
  const GAP15 = [
    "Cancel this governance proposal?\\n\\nCollected approvals are discarded. The vault itself is unaffected.",
    "Cancel this approval request?\\n\\nCollected approvals are discarded and nothing is broadcast. The vault itself is unaffected."
  ];
  for (const g of GAP15) assert.ok(APP_V4.includes(g), `the listed GAP-15 text is present (deferred LOW): ${g.slice(0, 50)}`);
  const hits = [];
  const CLAIM = /\b(?:discard|revok|cancel)\w*\b[^.]{0,60}?\b(?:approval|signature)s?\b|\bprevent\w*\b[^.]{0,60}?\bbroadcast/gi;
  for (const f of assets) {
    const src = fs.readFileSync(path.join(WEB_DIR, f), "utf8");
    /* the served text: every string literal of a script (and the text of index.html), split into sentences */
    const served = /\.html$/.test(f) ? [src.replace(/<[^>]*>/g, " ")] : (src.match(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g) ?? []);
    const sentences = served.flatMap((lit) => lit.split(/(?<=[.!?])\s+|\\n/));
    for (const s of sentences) {
      if (!/withdraw/i.test(s)) continue;
      /* RC45 C4-06a (tests only; writer classification WRITER-DECISION-C4-06-TEST-BUGS item 1, TEST BUG): the owner's
       * required sentence OWNER_SENTENCE (criterion 5; the B1-10 legs require it verbatim) negates both of its claims
       * with one "does not" ("does not revoke signatures or prevent … broadcast"), which the 24-character lead check
       * below cannot see. Exempt ONLY a match lying wholly inside an exact, verbatim occurrence of OWNER_SENTENCE;
       * every other text (an altered sentence, text around it in the same sentence) keeps the heuristic unchanged. */
      const ownerSpans = [];
      for (let i = s.indexOf(OWNER_SENTENCE); i !== -1; i = s.indexOf(OWNER_SENTENCE, i + 1)) ownerSpans.push([i, i + OWNER_SENTENCE.length]);
      for (const m of s.matchAll(CLAIM)) {
        if (ownerSpans.some(([from, to]) => m.index >= from && m.index + m[0].length <= to)) continue;
        const lead = s.slice(Math.max(0, m.index - 24), m.index);
        if (/\b(?:not|never|no|cannot|nor)\s+(?:\w+\s+)?$/i.test(lead)) continue; // a negated statement ("does not revoke …") is the required wording
        hits.push(`${f}: ${s.trim().slice(0, 180)}`);
      }
    }
  }
  assert.deepEqual(hits, [], "no served text claims withdrawal discards / revokes approvals or prevents a broadcast");
});

/* =============================== WEB: attribution answers =============================== */
test("RC45 L2-01: WEB-01 (FULL) the attributed ADVANCED answer (good) names A, its txid, 'broadcast outside PolicyVault' and the depth, says the root and the listed treasuries can be built again, and carries the GAP-2b warning with amendment A1-6's hold clause verbatim (R3N-B1 approved: never the not-approved 'and can hold the root again'); never the generic 'a submitted transaction was proven' and never recovered/restored/complete [RED on 8877dee]", () => {
  const { m } = mods();
  const d = m.describeReconcileOutcome(advanced("FULL"));
  assert.equal(d.status, "ADVANCED");
  assert.equal(d.level, "good", d.text);
  for (const s of [A_ID, X, "broadcast outside PolicyVault"]) assert.ok(d.text.includes(s), `names ${s} (${d.text})`);
  assert.match(d.text, /1,?000/, "states the depth");
  assert.match(d.text, /outside PolicyVault at any time/i, "GAP-2b: A's installed delegates can pay from the treasury outside PolicyVault at any time");
  /* R3N-B1a-inventory re-pin (addendum v2a item 6; writer amendment A1-6): the owner approved R3N-B1, so the
   * not-approved phrase is dropped and the FULL warning carries A1-6's clause (HOLD_CLAUSE, defined with the B1-10 legs) */
  assert.ok(d.text.includes(HOLD_CLAUSE), `GAP-2b: amendment A1-6's hold clause verbatim (${d.text})`);
  assert.doesNotMatch(d.text, /and can hold the root again/i, "GAP-2b: never the not-approved wording (R3N-B1 approved)");
  assert.ok(buildSentences(d.text).length > 0, "the buildability sentence is present (buildable.root true)");
  assert.doesNotMatch(d.text, /a submitted transaction/i, "never the generic replay wording");
  assert.doesNotMatch(d.text, NEVER_RECOVERED);
});

test("RC45 L2-01: WEB-01 (PARTIAL) the attributed ADVANCED answer is a warning: T1 UNRESOLVED, its hosted actions refused, a root FREEZE does not stop its delegates; never recovered/restored/complete [RED on 8877dee]", () => {
  const { m } = mods();
  const d = m.describeReconcileOutcome(advanced("PARTIAL"));
  assert.equal(d.status, "ADVANCED");
  assert.equal(d.level, "warn", d.text);
  assert.ok(d.text.includes(A_ID) && d.text.includes(X), "names A and its txid");
  assert.match(d.text, /UNRESOLVED/);
  assert.match(d.text, /refused/i, "its hosted actions are refused");
  assert.match(d.text, /FREEZE does not stop its delegates/i);
  assert.doesNotMatch(d.text, NEVER_RECOVERED);
});

test("RC45 L2-01: WEB-01 (SUBMIT_TO_RECORD) the UNKNOWN answer for a finalized request whose transaction is already on the chain names the request and its txid and tells the operator to press Submit on it, then Verify state [RED on 8877dee]", () => {
  const { m } = mods();
  const d = m.describeReconcileOutcome({ reconcile: { root: { status: "UNKNOWN", rootCovenantId: ROOT_ID, reason: "live outpoint gone, no claim", attribution: { outcome: "SUBMIT_TO_RECORD", requestId: A_ID, txId: X, requiredDepthDaa: "1000" } }, vaults: [] } });
  assert.ok(d.text.includes(A_ID), `names the request (${d.text})`);
  assert.ok(d.text.includes(X), "names the transaction");
  assert.match(d.text, /broadcast outside PolicyVault/);
  assert.match(d.text, /press Submit/i);
  assert.match(d.text, /Verify state/);
});

test("RC45 L2-01: WEB-05 buildability comes only from `buildable`: a root hold is a warning naming the request and its state, never 'can be built again'; buildable null is a warning that it was not determined; in PARTIAL the UNRESOLVED treasury is never listed buildable [RED on 8877dee]", () => {
  const { m } = mods();
  const held = m.describeReconcileOutcome(advanced("FULL", { holds: [{ scope: "root", requestId: "q-b-stranded", state: "AUTHORIZED" }], buildable: { root: false, treasuries: [] } }));
  assert.equal(held.level, "warn", held.text);
  assert.ok(held.text.includes("q-b-stranded") && held.text.includes("AUTHORIZED"), `names the hold (${held.text})`);
  assert.equal(buildSentences(held.text).length, 0, "no buildability claim while a request holds the root");
  const unknown = m.describeReconcileOutcome(advanced("FULL", { holds: null, buildable: null }));
  assert.equal(unknown.level, "warn", unknown.text);
  assert.match(unknown.text, /not determined/i);
  assert.equal(buildSentences(unknown.text).length, 0, "no buildability claim when it was not determined");
  const partial = m.describeReconcileOutcome(advanced("PARTIAL"));
  const claims = buildSentences(partial.text);
  assert.ok(claims.length > 0, `the root and T2 are named buildable (${partial.text})`);
  for (const s of claims) assert.ok(!s.includes(T1.slice(0, 8)), `the UNRESOLVED treasury is never listed buildable (${s})`);
  assert.ok(claims.some((s) => s.includes(T2.slice(0, 8))), "T2 is listed buildable");
});

test("RC45 L2-01: WEB-06 a CHAIN_VERIFIED request carrying a bound PARTIAL attribution marker reads as the warning 'Chain-verified root move — treasury UNRESOLVED', not as proven; FULL-marked and unmarked CHAIN_VERIFIED requests keep the C3 meaning [RED on 8877dee]", () => {
  const { m } = mods();
  const partial = detail(m, chainVerified({ outOfBandAttribution: marker("PARTIAL") }));
  assert.ok(partial.includes("Chain-verified root move — treasury UNRESOLVED"), `the warn title (${partial.slice(0, 600)})`);
  assert.match(partial, /broadcast outside PolicyVault/);
  assert.doesNotMatch(partial, /This is proven\./, "never the generic proven meaning");
  assert.doesNotMatch(partial, /Complete — verified on the chain/);
  for (const req of [chainVerified({ outOfBandAttribution: marker("FULL") }), chainVerified()]) {
    const t = detail(m, req);
    assert.match(t, /This is proven\./, "the C3 meaning is unchanged");
    assert.doesNotMatch(t, /treasury UNRESOLVED/);
  }
});

test("RC45 L2-01: WEB-04 SUPERSEDED is a closed, terminal request outcome ('another confirmed transaction spent an output it needs; nothing from it happened'), never verified, never offered a withdrawal [RED on 8877dee]", () => {
  const { m } = mods();
  const o = m.requestOutcome("SUPERSEDED");
  assert.match(o.meaning, /another confirmed transaction spent an output it needs/i, `${o.title}: ${o.meaning}`);
  assert.match(o.meaning, /nothing from it happened/i);
  assert.equal(m.isVerifiedRequestOutcome("SUPERSEDED"), false);
  assert.equal(m.withdrawEligibility(kasRuleChange({ state: "SUPERSEDED" })).kind, "none", "a SUPERSEDED request holds no reservation");
});

test("RC45 L2-01: WEB-02 refusal explanations: RECORDED_OUTPUT_SPENT (nothing recorded; press Verify state; build again ONLY IF Verify then shows the root verified with no request holding it; an UNKNOWN answer keeps the build refused) and TREASURY_STATE_UNRESOLVED (the writer decision's binding explanation verbatim: hosted actions stay closed; a later Verify restores them only if it finds the expected output unspent again; otherwise only the owners' direct on-chain exit can act — never 'Verify does not resolve it in this release') [RED on 8877dee]", () => {
  const spent = RX.explain("RECORDED_OUTPUT_SPENT");
  assert.ok(spent, "RECORDED_OUTPUT_SPENT has a closed explanation");
  const st = `${spent.title} ${spent.meaning ?? ""} ${(spent.next ?? []).join(" ")}`;
  assert.match(st, /nothing was recorded/i);
  assert.match(st, /Verify state/);
  assert.match(st, /only if/i, "build again is conditional (never an unconditional 'build again')");
  assert.match(st, /UNKNOWN/);
  const unresolved = RX.explain("TREASURY_STATE_UNRESOLVED");
  assert.ok(unresolved, "TREASURY_STATE_UNRESOLVED has a closed explanation");
  const ut = `${unresolved.title} ${unresolved.meaning ?? ""} ${(unresolved.next ?? []).join(" ")}`.replace(/\s+/g, " ");
  assert.ok(ut.includes(UNRESOLVED_EXPLANATION), `the binding TREASURY_STATE_UNRESOLVED explanation (writer decision 'wording after the PARTIAL upgrade' item 1), verbatim; it says: ${ut}`);
  assert.doesNotMatch(ut, /does not resolve it in this release/i, "the superseded 'Verify does not resolve it in this release' text is gone");
  const uhtml = RX.renderRefusalHtml({ summary: "Build refused", code: "TREASURY_STATE_UNRESOLVED", message: "wallet-requests-v7: treasury T1 is UNRESOLVED after request A's transaction" });
  assert.ok(uhtml.includes("TREASURY_STATE_UNRESOLVED"), "the refusal code is shown (it names the state)");
  assert.ok(text(uhtml).includes(UNRESOLVED_EXPLANATION), `the rendered refusal carries the binding explanation (${text(uhtml).slice(0, 600)})`);
  const html = RX.renderRefusalHtml({ summary: "Build refused", code: "RECORDED_OUTPUT_SPENT", message: "wallet-requests-v7: the root input 11:0 is not reported unspent" });
  assert.ok(html.includes("RECORDED_OUTPUT_SPENT") && html.includes("not reported unspent"), "the code and the server's message are shown");
});

test("RC45 L2-01: WEB-03 a treasury whose summary carries stateUnresolved shows the 'STATE UNRESOLVED' badge and labels its delegates and balance as the last record [RED on 8877dee]", () => {
  const { km } = mods();
  const G = FX.genesis;
  const vault = { vaultId: G.summary.vaultId, label: "Ops treasury", status: "ACTIVE", orgRootCovenantId: G.summary.orgRootCovenantId, contractVersion: KAS_PROFILE, candidateStatus: "CANDIDATE", profile: "kas", generation: 1, recoveryPk: G.summary.recoveryPk, agents: G.summary.agents, approvers: [], approvalM: "0", live: { covenantId: G.summary.covenantId, outpoint: { transactionId: G.txId, index: 0 }, protectedValueKas: "100", feeReserveKas: "5", totalKas: "105", paused: false, policyNonce: "0" }, stateUnresolved: { requestId: A_ID, txId: X } };
  const root = { ...ROOT, rootCovenantId: G.summary.orgRootCovenantId, vaults: [vault.vaultId] };
  const html = km.renderKasVaultPanelHtml(vault, root, { viewerXOnly: K(0x71) });
  assert.match(html, /STATE UNRESOLVED/, "the badge");
  assert.match(text(html), /last[- ]record/i, "the delegates and balance are labelled as the last record");
  const plain = km.renderKasVaultPanelHtml({ ...vault, stateUnresolved: null }, root, { viewerXOnly: K(0x71) });
  assert.doesNotMatch(plain, /STATE UNRESOLVED/, "no badge without the state");
});

/* =============================== R3N-B1 (B1-10): the served texts of the submit read and the withdrawal ===============================
 * Contract rc45-l201-contract-03 (addendum v2b revision 3 §2 S3, §4 "Served text T-B1", §5 R4, §9; writer amendment A1-6,
 * which prevails). RED until C4-06 serves them. The owner's sentence (criterion 5 of the owner's direction)
 * opens T-B1 verbatim; A1-6's hold clause replaces the not-approved "and can hold the root again" meaning
 * (it says the hold lasts until a withdrawal, or longer where a withdrawal cannot be proven safe — never that it always
 * ends). New legs only; of the legs above only WEB-01 (FULL) changed (re-pinned to A1-6 by R3N-B1a-inventory). */
const OWNER_SENTENCE = "Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast.";
const HOLD_CLAUSE = "holds the root until it is withdrawn (two steps, at least 1,000 DAA apart), or longer in the disclosed cases where a withdrawal cannot be proven safe";
const B1_FEE_OUT = { transactionId: "f1".repeat(32), index: 2 };
const spentObservation = () => ({ schema: "policyvault-input-spent-observation/1", requestId: A_ID, txId: X, anchor: { hash: "77".repeat(32), daaScore: "546000000" }, virtualDaa: "546000037", at: "2000-01-01T00:00:00.000Z", spent: [{ index: 2, role: "fee", outpoint: B1_FEE_OUT, existence: { path: "E1", block: null, daaScore: "544000000", finalAt: "546000037" } }] });
const spentWithdrawal = () => ({ schema: "policyvault-input-spent-withdrawal/1", requestId: A_ID, txId: X, anchor: { hash: "77".repeat(32), daaScore: "546000000" }, withdrawnAt: "2000-01-01T00:10:00.000Z", observedVirtualDaa: "546001000", depthDaa: "1000", sink: "78".repeat(32), spent: spentObservation().spent, windowBlocks: 21, scanBlocks: 21, scanBatches: 1 });
const finalizedB1 = (over = {}) => kasRuleChange({ state: "SIGNED", finalizedTxHex: "00", finalTransaction: { version: 1, inputs: [], outputs: [] }, ...over });
/* every window.confirm(...) of app-v4.js as rendered: a flagged one for both values of its flag, a plain one as is */
function appV4AllConfirms() {
  const out = [], errors = [];
  for (const m of APP_V4.matchAll(/window\.confirm\(/g)) {
    const start = m.index + "window.confirm(".length;
    let expr;
    try { expr = exprUntil(APP_V4, start, ""); } catch (e) { errors.push(e.message); continue; }
    const flag = /^\s*([A-Za-z_$][\w$]*)\s*\?/.exec(expr);
    try {
      if (flag) { out.push(norm(renderServed(expr, { [flag[1]]: true }))); out.push(norm(renderServed(expr, { [flag[1]]: false }))); }
      else out.push(norm(renderServed(expr, {})));
    } catch (e) { errors.push(`${expr.slice(0, 60)}: ${e.message}`); }
  }
  return { out, errors };
}
const NO_REBUILD = /\b(?:build (?:it )?again|rebuild|re-build|replace (?:it|this request)|start a replacement|build a new)\b/i;

test("RC45 R3N-B1: B1-10 (T-B1) a REFUSED request withdrawn by the input-spent withdrawal (inputSpentWithdrawal) reads 'Withdrawn — PolicyVault will not send it' followed by T-B1, whose opening sentence is the owner's verbatim and which states that the spend is final at 1,000 DAA and that withdrawing broadcasts nothing; never recovered/restored/complete [RED on 5b6d8e9: no such outcome]", () => {
  const { m } = mods();
  const t = detail(m, finalizedB1({ state: "REFUSED", inputSpentWithdrawal: spentWithdrawal() }));
  assert.ok(t.includes("Withdrawn — PolicyVault will not send it"), `the title (${t.slice(0, 600)})`);
  assert.ok(t.includes(OWNER_SENTENCE), `T-B1 opens with the owner's sentence verbatim (${t.slice(0, 900)})`);
  assert.match(t, /final at 1,000 DAA/i, "the spend is final at 1,000 DAA");
  assert.match(t, /broadcasts nothing/i, "withdrawing broadcasts nothing");
  assert.doesNotMatch(t, NEVER_RECOVERED);
});

test("RC45 R3N-B1: B1-10 (the withdrawal offer, R4) withdrawEligibility: a SIGNED request carrying a bound inputSpentObservation is offered the withdrawal (kind 'withdraw') and its reason carries the owner's sentence verbatim; a SIGNED request whose Submit this page saw answered 409 RECORDED_OUTPUT_SPENT with withdrawal TWO_STEP (serverRefusedSpent) is offered it too, a SIGNED succession likewise; a plain SIGNED request keeps 'resume' [RED on 5b6d8e9: a SIGNED request is always 'resume']", () => {
  const { m } = mods();
  const anchored = m.withdrawEligibility(finalizedB1({ inputSpentObservation: spentObservation() }));
  assert.equal(anchored.kind, "withdraw", anchored.reason);
  assert.ok(String(anchored.reason).includes(OWNER_SENTENCE), `the owner's sentence (${anchored.reason})`);
  const refused = m.withdrawEligibility(finalizedB1(), { serverRefusedSpent: true });
  assert.equal(refused.kind, "withdraw", refused.reason);
  assert.ok(String(refused.reason).includes(OWNER_SENTENCE), `the owner's sentence (${refused.reason})`);
  const succession = m.withdrawEligibility(finalizedB1({ action: "succession", vaultOperations: [], inputSpentObservation: spentObservation() }));
  assert.equal(succession.kind, "withdraw", succession.reason);
  assert.equal(m.withdrawEligibility(finalizedB1()).kind, "resume", "a plain SIGNED request keeps resume");
});

test("RC45 R3N-B1: B1-10 (T-B1 in the confirmation) app-v4's confirmation of the input-spent withdrawal, as rendered, carries T-B1: the owner's sentence verbatim, the spend final at 1,000 DAA, the reservation released, nothing broadcast [RED on 5b6d8e9: no such confirmation]", () => {
  const { out, errors } = appV4AllConfirms();
  const tb1 = out.filter((c) => c.includes(OWNER_SENTENCE));
  assert.ok(tb1.length >= 1, `a confirmation carries the owner's sentence (renderings ${out.length}; not evaluated: ${errors.join("; ") || "none"})`);
  assert.ok(tb1.some((c) => /final at 1,000 DAA/i.test(c) && /broadcasts nothing/i.test(c)), `it states the 1,000-DAA finality and that nothing is broadcast (${tb1.join(" | ").slice(0, 900)})`);
});

test("RC45 R3N-B1: B1-10 (refusal explanations) refusal-explain has closed explanations for SUBMIT_INPUT_UNRESOLVED (nothing recorded or broadcast; Verify state), WITHDRAWAL_DEPTH_PENDING (two steps at least 1,000 DAA apart) and FEE_INPUT_NOT_LIVE (the fee input; nothing recorded; the root not reserved); the submit-context RECORDED_OUTPUT_SPENT (the server's submit message, extra.submitRead TWO_STEP) explains the two-step withdrawal and Verify state; none of them offers a build, rebuild or replacement [RED on 5b6d8e9: no such explanations]", () => {
  const all = (e) => `${e.title} ${e.meaning ?? ""} ${(e.next ?? []).join(" ")}`.replace(/\s+/g, " ");
  const unresolved = RX.explain("SUBMIT_INPUT_UNRESOLVED");
  assert.ok(unresolved, "SUBMIT_INPUT_UNRESOLVED has a closed explanation");
  assert.match(all(unresolved), /nothing was recorded/i);
  assert.match(all(unresolved), /Verify state/);
  assert.doesNotMatch(all(unresolved), NO_REBUILD);
  const pending = RX.explain("WITHDRAWAL_DEPTH_PENDING");
  assert.ok(pending, "WITHDRAWAL_DEPTH_PENDING has a closed explanation");
  assert.match(all(pending), /1,000 DAA/);
  assert.match(all(pending), /two steps|second step/i);
  assert.doesNotMatch(all(pending), NO_REBUILD);
  const fee = RX.explain("FEE_INPUT_NOT_LIVE");
  assert.ok(fee, "FEE_INPUT_NOT_LIVE has a closed explanation");
  assert.match(all(fee), /fee input/i);
  assert.match(all(fee), /nothing was recorded/i);
  assert.match(all(fee), /not reserved/i);
  const submitMsg = "wallet-requests-v7: The recorded fee output f1…:2 that this finalized request spends is no longer reported unspent, while the root output it spends still is, so this request's own transaction has not spent it: PolicyVault treats it as spent by another transaction. Nothing was recorded or broadcast; the request still reserves the root.";
  const extra = { submitRead: { finding: "CONFLICTING_SPEND", role: "fee", outpoint: B1_FEE_OUT, withdrawal: "TWO_STEP", existence: "E1", existenceGap: null } };
  const spent = RX.explain("RECORDED_OUTPUT_SPENT", submitMsg, extra);
  assert.ok(spent, "RECORDED_OUTPUT_SPENT (submit) has a closed explanation");
  assert.match(all(spent), /withdraw/i, "the two-step withdrawal is explained");
  assert.match(all(spent), /two steps|second step|1,000 DAA/i);
  assert.match(all(spent), /Verify state/);
  assert.doesNotMatch(all(spent), NO_REBUILD, "no build, rebuild or replacement next to the submit refusal");
  const html = RX.renderRefusalHtml({ summary: "Submit refused", code: "RECORDED_OUTPUT_SPENT", message: submitMsg, extra });
  assert.doesNotMatch(text(html), NO_REBUILD, "the rendered submit refusal offers no build, rebuild or replacement");
});

test("RC45 R3N-B1: B1-10 (R4 served strings) the served assets say 'Submit refused — nothing was recorded or sent' for a TWO_STEP refusal (never 'outcome uncertain' for it), offer 'Finish withdrawal' when the root's pointer names a REFUSED request, and carry the retention note (the withdrawal must start while the node holds the build's history, about 30 hours by default) [RED on 5b6d8e9: none of these strings is served]", () => {
  const assets = fs.readdirSync(WEB_DIR).filter((f) => /\.(js|html)$/.test(f)).map((f) => fs.readFileSync(path.join(WEB_DIR, f), "utf8")).join("\n");
  assert.ok(assets.includes("Submit refused — nothing was recorded or sent"), "the TWO_STEP refusal summary");
  assert.ok(assets.includes("Finish withdrawal"), "the finish-withdrawal offer");
  assert.match(assets, /about 30 hours/i, "the retention note");
});

test("RC45 R3N-B1: B1-10 (A1-6) the attributed ADVANCED answer (FULL) carries the GAP-2b warning with the amendment's hold clause verbatim — the race-losing request holds the root until withdrawn in two steps, or longer where a withdrawal cannot be proven safe — and never says the hold always ends [RED on 5b6d8e9: the clause is not served]", () => {
  const { m } = mods();
  const d = m.describeReconcileOutcome(advanced("FULL"));
  assert.ok(d.text.includes(HOLD_CLAUSE), `the A1-6 clause verbatim (${d.text})`);
  assert.doesNotMatch(d.text, /\b(?:always|eventually) (?:ends|released|clears)\b/i, "never that the hold always ends");
  assert.doesNotMatch(d.text, NEVER_RECOVERED);
});
