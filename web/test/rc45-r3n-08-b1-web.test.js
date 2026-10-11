"use strict";
/*
 * RC45 R3N-B1 (B1-10, web) — the request modal's Submit offer, app-v4's R4 answer wiring and the unreadable-root modal,
 * driven BEHAVIOURALLY on the served page. Internal RED-first regression material for the RC45 candidate (tests only,
 * C4-06b); not an external engagement of any kind.
 *
 * Binding: rc45-l201-contract-03 (addendum v2b revision 3 §5 R3/R4, §6 "X wins during the wait"; writer amendment A1)
 * and its writer clarification 02, which prevails where they conflict:
 *   item 1  Submit stays offered for every SIGNED, never-attempted request, whether or not a withdrawal anchor exists;
 *           the server's submit read decides (a 409 with nothing written, or the existing completion route). After a
 *           CANNOT_REJECT with a non-pending finding (ROOT_INPUT_NOT_LIVE, ACCEPTED_IN_WINDOW, IN_TRANSACTION_POOL,
 *           UNSTABLE), or after a Verify answering SUBMIT_TO_RECORD that names this request, the next-step text points to
 *           Submit, then Verify state; while a withdrawal is pending (WITHDRAWAL_DEPTH_PENDING, anchor present) it offers
 *           Wait, step 2 or Submit and claims nothing about which will succeed (R3: "Anchor present: Wait, step 2, or
 *           Submit").
 *   item 2  app-v4's R4 answer wiring is pinned by behaviour, not by string presence (C4-06 check F02): the TWO_STEP 409
 *           is recorded and the withdrawal offered (mutant X19); "nothing was recorded or sent" only for the structured
 *           refusal, never for a transport loss after a broadcast or another failure (X18); the CANNOT_REJECT finding is
 *           shown (X20); "Finish withdrawal" when the root's pointer names a REFUSED W8 request (X15).
 *   item 3  when the root cannot be re-read, the request modal states that the reservation could not be confirmed and
 *           offers Verify state; it never says that the root is no longer reserved (C4-06 check F03).
 * The owner's direction: if this request spent the input, preserve its
 * completion, attribution or reconciliation path; uncertainty never justifies withdrawal, premature claim release or a
 * retry under a new key. Submitting the same signed bytes is not a retry under a new key (clarification 02 item 1).
 *
 * Layer: BROWSER (jsdom). The real web/index.html with the real served scripts (core-bundle, setup-ui, org-root-ui,
 * kas-vault-ui, refusal-explain, app-v4) — the request modal is opened from the root detail exactly as an owner opens it
 * and its buttons are clicked. Only the wallet session and the HTTP answers are doubles: every request is intercepted at
 * a fixture origin (no network), every wallet-signing method refuses, and the fixtures are the public production-byte
 * v0.7-kas manifests (core/explain/test/fixtures/v7-kas-manifests.json; synthetic repeated-byte keys, no key material).
 * Labels: [RED on 8900cf5: <reason>] fails on the C4-06a HEAD for the stated reason; [PIN: holds on 8900cf5] holds there
 * and must keep holding. Each W leg names the C4-06 checker mutant it catches (X15, X18, X19, X20). The next-step text is
 * read from the request detail's "Next" row; Submit is "offered" when its button is rendered and enabled.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("../../sdk/node_modules/jsdom");

const WEB_DIR = path.join(__dirname, "..");
const REPO = path.join(WEB_DIR, "..");
const HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const SCRIPTS = ["core-bundle.js", "setup-ui.js", "org-root-ui.js", "kas-vault-ui.js", "refusal-explain.js", "app-v4.js"]
  .map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const FX = JSON.parse(fs.readFileSync(path.join(REPO, "core/explain/test/fixtures/v7-kas-manifests.json"), "utf8"));

/* ---------------- fixtures: B = a finalized ownerPause on treasury T, under the root's authorize action ---------------- */
const PAUSE = FX.manifests.find((m) => m.name === "vault_owner_pause");
assert.ok(PAUSE, "fixture vault_owner_pause");
const KAS = "policyvault-0.7-kas";
const ROOT_ID = PAUSE.manifest.root.covenantId;
const TREASURY = PAUSE.manifest.vaultOperations[0].vaultId;
const X = PAUSE.txId; // B's transaction id
const REQ_ID = "q-b1-web";
const OWNERS = ["71", "72", "73"].map((b) => b.repeat(32));
const VIEWER = { address: "kaspatest:b1owner3", xonly: OWNERS[2] };
const FEE_IN = JSON.parse(PAUSE.unsignedSafeJson).inputs[2]; // B's fee input (the third frozen input)
const FEE_OUT = { transactionId: FEE_IN.transactionId, index: FEE_IN.index };
const ANCHOR_DAA = 546000000n;
const OWNER_SENTENCE = "Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast.";

const rootRecord = (pendingRequestId = REQ_ID) => ({
  rootCovenantId: ROOT_ID, orgId: PAUSE.manifest.root.orgId, label: "B1 root", networkId: "testnet-10", ownerSlotsActive: 3, ownerM: "2", frozen: false,
  slots: OWNERS.map((k, i) => ({ slot: i + 1, publicKey: k, address: `kaspatest:b1owner${i + 1}`, label: `Owner ${i + 1}` })),
  template: PAUSE.manifest.root.template, state: PAUSE.manifest.rootState.before.state,
  live: { outpoint: { transactionId: "7c".repeat(32), index: 0 }, blockDaaScore: "1000" }, pendingRequestId, vaults: []
});
/* the finalized (SIGNED), never-attempted request as the server presents it */
const signedRequest = (over = {}) => ({
  schemaVersion: "policyvault-org-root-request/1", id: REQ_ID, rootCovenantId: ROOT_ID, orgId: PAUSE.manifest.root.orgId, contractVersion: "policyvault-0.7-root",
  kind: "rootAction", action: "authorize", actionClass: PAUSE.manifest.action.authorityClass,
  vaultOperations: [{ vaultId: TREASURY, profile: KAS, action: "ownerPause", params: {} }],
  manifest: PAUSE.manifest, redeemScripts: PAUSE.redeemScripts, manifestHash: PAUSE.manifest.manifestHash, signerVisibleDigest: PAUSE.manifest.manifestHash,
  requiredApprovals: PAUSE.manifest.action.requiredApprovals, signaturesPresent: 2,
  slots: OWNERS.map((k, i) => ({ slot: i + 1, publicKey: k, address: `kaspatest:b1owner${i + 1}`, label: `Owner ${i + 1}`, status: i < 2 ? "SIGNED" : "PENDING", signedAt: null, responseEnvelopeHash: null })),
  state: "SIGNED", rootInputIndex: PAUSE.rootInputIndex, txId: X,
  transaction: { unsignedSafeJson: PAUSE.unsignedSafeJson, frozenCanonicalJson: PAUSE.frozenCanonicalJson, signInputs: PAUSE.signInputs },
  finalizedTxHex: "00", finalTransaction: { version: 1, inputs: [], outputs: [] }, ...over
});
const existenceE1 = () => ({ path: "E1", block: null, daaScore: "544000000", finalAt: "546000037" });
/* withdrawal step 1's anchor (contract-03 §4 W6 "Anchor field") */
const anchorRecord = () => ({ schema: "policyvault-input-spent-observation/1", requestId: REQ_ID, txId: X, anchor: { hash: "77".repeat(32), daaScore: String(ANCHOR_DAA) }, virtualDaa: "546000037", at: "2026-10-10T00:00:00.000Z", spent: [{ index: 2, role: "fee", outpoint: FEE_OUT, existence: existenceE1() }] });
/* the W7b withdrawal record */
const withdrawalRecord = () => ({ schema: "policyvault-input-spent-withdrawal/1", requestId: REQ_ID, txId: X, anchor: anchorRecord().anchor, withdrawnAt: "2026-10-10T00:10:00.000Z", observedVirtualDaa: "546001000", depthDaa: "1000", sink: "78".repeat(32), spent: anchorRecord().spent, windowBlocks: 21, scanBlocks: 21, scanBatches: 1 });
const anchored = (over = {}) => signedRequest({ inputSpentObservation: anchorRecord(), ...over });
const withdrawnW8 = () => signedRequest({ state: "REFUSED", error: "withdrawn by an owner", inputSpentWithdrawal: withdrawalRecord() });

/* the server's answers (the error body spreads the refusal's structured extra, srv:125-127) */
const err = (status, code, message, extra = {}) => ({ status, body: { error: { code, message, ...extra } } });
const twoStep = () => err(409, "RECORDED_OUTPUT_SPENT", `wallet-requests-v7: The recorded fee output ${FEE_OUT.transactionId}:${FEE_OUT.index} that this finalized request spends is no longer reported unspent, while the root output it spends still is, so this request's own transaction has not spent it: PolicyVault treats it as spent by another transaction. Nothing was recorded or broadcast; the request still reserves the root.`,
  { submitRead: { finding: "CONFLICTING_SPEND", role: "fee", outpoint: FEE_OUT, withdrawal: "TWO_STEP", existence: "E1", existenceGap: null } });
const submitUnresolved = (finding) => err(409, "SUBMIT_INPUT_UNRESOLVED", `wallet-requests-v7: submit read: ${finding}; nothing was recorded or broadcast`,
  { submitRead: { finding, role: finding === "ROOT_INPUT_NOT_LIVE" ? "root" : "fee", outpoint: FEE_OUT, withdrawal: "NONE", existence: null, existenceGap: finding === "INPUT_EXISTENCE_UNPROVEN" ? "CREATOR_NOT_LOCATED" : null } });
const cannotReject = (finding) => err(409, "CANNOT_REJECT", `wallet-requests-v7: request ${REQ_ID} cannot be withdrawn now (${finding}); nothing was written`, { withdrawal: { finding } });
const depthPending = () => err(409, "WITHDRAWAL_DEPTH_PENDING", `wallet-requests-v7: withdrawal step recorded its chain anchor; withdraw again from DAA ${ANCHOR_DAA + 1000n} to DAA ${ANCHOR_DAA + 12000n}. ${OWNER_SENTENCE}`,
  { earliestDaa: String(ANCHOR_DAA + 1000n), latestDaa: String(ANCHOR_DAA + 12000n) });
const submitToRecord = (requestId = REQ_ID) => ({ body: { reconcile: { root: { status: "UNKNOWN", rootCovenantId: ROOT_ID, reason: "the live root outpoint is spent and no claim names its spender", attribution: { outcome: "SUBMIT_TO_RECORD", requestId, txId: X, requiredDepthDaa: "1000" } }, vaults: [] } } });

/* ---------------- text matchers ---------------- */
const SUBMIT_THEN_VERIFY = /\bsubmit\b[^.]{0,160}?\bthen\b[^.]{0,80}?\bVerify state\b/i;
const NO_OUTCOME_CLAIM = /\b(?:will|would) (?:succeed|work|complete|go through|withdraw it|be (?:withdrawn|accepted|sent|confirmed|released))\b|\bguarantee/i;
const NEVER_RECOVERED = /\b(?:recovered|restored|repaired|complete)\b/i;
const NOTHING_SENT = /nothing was recorded or (?:sent|broadcast)/i;
const NO_REBUILD = /\b(?:build (?:it )?again|rebuild|re-build|replace (?:it|this request)|start a replacement|build a new)\b/i;
const RELEASED_CLAIM = /no longer reserves the root|(?:reservation|root) (?:is|was|has been) (?:released|freed|cleared)|new request can be started/i;
const NOT_CONFIRMED = /reserv\w*[^.]{0,160}?\b(?:could not|cannot|can't|was not|is not|not) (?:be )?(?:confirm|read|check|determin|verif)\w*|\b(?:could not|cannot|can't) (?:be )?(?:confirm|read|check|determin|verif)\w*[^.]{0,160}?\breserv/i;

/* ---------------- the served page in jsdom (only HTTP answers and the wallet are doubles) ---------------- */
function capabilities(networkId) {
  return { networkId, contract: { creatableCovenantVersions: ["policyvault-0.4.1", "policyvault-0.7-root", "policyvault-0.7-kas"] } };
}
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(pred, ms = 8000) { const t0 = Date.now(); while (!pred() && Date.now() - t0 < ms) await pause(5); return pred(); }
/* visible text: text nodes joined with spaces (jsdom's textContent runs adjacent blocks together) */
function visible(el) {
  if (!el) return "";
  const out = [];
  const walk = (n) => { if (n.nodeType === 3) out.push(n.nodeValue); else if (n.nodeType === 1 && !["SCRIPT", "STYLE"].includes(n.tagName)) n.childNodes.forEach(walk); };
  walk(el);
  return out.join(" ").replace(/\s+/g, " ").trim();
}

/*
 * `routes`: { "METHOD /route": (body, n) => answer } where n counts that route's calls (1-based) and answer is
 * { status?, body } | { noJson: status } (a body that is not JSON) | { transportLoss: true } (fetch rejects: the
 * connection was lost, possibly after the server broadcast).
 */
async function loadPage(t, { routes = {}, root = () => rootRecord() } = {}) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(e.message));
  const dom = new JSDOM(HTML, { url: "https://policyvault-fixture.invalid/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  t.after(async () => { await pause(20); dom.window.close(); });
  const { window } = dom;
  const document = window.document;
  const calls = [], unexpected = [], counts = new Map();
  let signingCalls = 0;
  /* a response body is parsed in the page's own realm, as a browser's fetch does */
  const reply = (body, status = 200) => ({ ok: status < 400, status, statusText: String(status), json: async () => window.JSON.parse(JSON.stringify(body)) });
  const confirms = [];
  window.confirm = (message) => { confirms.push(String(message)); return true; };
  const allRoutes = {
    [`GET /org-roots/${ROOT_ID}`]: (_, n) => ({ body: { orgRoot: root(n) } }),
    ...routes
  };
  window.fetch = async (url, options = {}) => {
    const target = new URL(url, window.location);
    assert.equal(target.origin, window.location.origin, "fixture never reaches an external origin");
    const method = options.method || "GET";
    const route = target.pathname.replace(/^\/api\/v1/, "");
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ method, route, body });
    const key = `${method} ${route}`;
    if (allRoutes[key]) {
      const n = (counts.get(key) || 0) + 1;
      counts.set(key, n);
      const a = await allRoutes[key](body, n);
      if (a.transportLoss) throw new window.TypeError("Failed to fetch");
      if (a.noJson) return { ok: false, status: a.noJson, statusText: "Bad Gateway", json: async () => { throw new window.SyntaxError("Unexpected token '<', \"<html>\" is not valid JSON"); } };
      return reply(a.body, a.status ?? 200);
    }
    if (method === "GET" && route === "/network/status") return reply({ networkId: "testnet-10", virtualDaaScore: String(ANCHOR_DAA + 500n) });
    if (method === "GET" && route === "/health") return reply({ networkId: "testnet-10" });
    if (method === "GET" && route === "/capabilities") return reply(capabilities("testnet-10"));
    if (method === "GET" && route === "/organizations") return reply({ organizations: [], assignments: {} });
    if (method === "GET" && route === "/org-roots") return reply({ orgRoots: [root(0)] });
    if (method === "GET" && route === "/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: [] });
    if (method === "GET" && route === "/wallet/v7/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v7/requests") return reply({ requests: [] });
    if (method === "GET" && route === "/audit") return reply({ events: [] });
    unexpected.push(key);
    return reply({ error: { code: "FIXTURE_UNMAPPED", message: `unmapped fixture route ${key}` } }, 404);
  };
  const refuse = async () => { signingCalls += 1; throw new Error("this leg never invokes wallet signing"); };
  const snapshot = { connected: true, ready: true, address: VIEWER.address, xonly: VIEWER.xonly, network: "testnet-10", serverNetwork: "testnet-10", auth: "AUTHENTICATED", provider: "fixture", adapter: { signInputs: refuse, signPskt: refuse, signAuthMessage: refuse } };
  window.PolicyVaultHealthPromise = Promise.resolve({ networkId: "testnet-10" });
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { fn(snapshot); return () => {}; } };
  for (const { name, source } of SCRIPTS) window.eval(`${source}\n//# sourceURL=${name}`);
  const wired = () => { const tab = document.querySelector('.v4-tab[data-view="orgs"]'); return !!(tab && typeof tab.onclick === "function"); };
  if (!(await until(wired, 3000))) window.dispatchEvent(new window.Event("DOMContentLoaded"));
  assert.ok(await until(wired, 3000), "app navigation initialized");
  const api = window.PolicyVaultV4;
  document.querySelector('.v4-tab[data-view="orgs"]').click();
  assert.ok(await until(() => api._state.view === "orgs" && document.querySelector(`[data-viewroot="${ROOT_ID}"]`)), "the organizations view lists the root");
  t.after(() => {
    assert.deepEqual(unexpected, [], "every HTTP operation was explicitly stubbed");
    assert.deepEqual(errors, [], "no uncaught DOM errors");
    assert.equal(signingCalls, 0, "no wallet signing invoked");
  });
  const h = {
    window, document, calls, confirms,
    modal: () => document.getElementById("v4-modal"),
    notice: () => document.getElementById("v4-notice"),
    posts: (route) => calls.filter((c) => c.method === "POST" && c.route === route),
    card: () => document.getElementById("v4-modal").querySelector(`[data-org-root-request="${REQ_ID}"]`),
    q: (sel) => document.getElementById("v4-modal").querySelector(sel)
  };
  return h;
}
const REQ_ROUTE = `/org-roots/${ROOT_ID}/requests/${REQ_ID}`;
const SUBMIT_ROUTE = `${REQ_ROUTE}/submit`, REJECT_ROUTE = `${REQ_ROUTE}/reject`, RECONCILE_ROUTE = `/org-roots/${ROOT_ID}/reconcile`;

/* open the root detail, then its pending request — the way an owner reaches the request modal */
async function openRequest(h) {
  h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
  assert.ok(await until(() => h.document.getElementById("v4-orgroot-detail-close")), "the root detail opened");
  const open = h.q(`[data-vieworequest="${REQ_ID}"]`);
  assert.ok(open, "the root detail offers its pending request");
  open.click();
  assert.ok(await until(() => h.card() && h.q("#v4-orgroot-request-close")), "the request modal opened");
  await pause(30);
}
/* click a modal button and wait until the modal has been painted again from the re-read request */
async function clickAndRepaint(h, el, label) {
  assert.ok(el, `${label}: the button is present`);
  const before = h.modal().firstElementChild;
  before.setAttribute("data-c406b-painted-before", "1");
  el.click();
  const repainted = await until(() => !h.modal().querySelector("[data-c406b-painted-before]") && h.card(), 5000);
  assert.ok(repainted, `${label}: the request modal was painted again after the answer (notice: ${visible(h.notice()).slice(0, 400)})`);
  await pause(30);
}
const submitButton = (h) => h.q(`[data-rootsubmit="${REQ_ID}"]`);
const verifyButton = (h) => h.q(`[data-rootreconcile-request="${REQ_ID}"]`);
const step1Button = (h) => h.q(`[data-rootreject="${REQ_ID}"][data-rootspent="step1"]`);
const step2Button = (h) => h.q(`[data-rootreject="${REQ_ID}"][data-rootspent="step2"]`);
const finishButton = (h) => h.q(`[data-rootreject="${REQ_ID}"][data-rootfinish]`);
/* the modal's "Next" row: the next-step text */
function nextText(h) {
  const card = h.card();
  const row = card ? [...card.querySelectorAll(".rv-row")].find((r) => { const k = r.querySelector(".rv-k"); return k && k.textContent.trim() === "Next"; }) : null;
  return row ? visible(row.querySelector(".rv-v")) : "";
}
function assertSubmitOffered(h, label) {
  const b = submitButton(h);
  assert.ok(b, `${label}: a Submit button is rendered`);
  assert.equal(b.disabled, false, `${label}: Submit is offered (enabled) for this SIGNED, never-attempted request — the server's submit read decides (clarification 02 item 1); its title says: ${b.getAttribute("title") || "(none)"}`);
}

/* ============================== item 1: the Submit offer ============================== */
test("RC45 R3N-B1 clarification 02: S-01 a SIGNED, never-attempted request without a withdrawal anchor offers Submit, and pressing it posts this request's Submit exactly once (no automatic retry) [PIN: holds on 8900cf5]", async (t) => {
  const s = { request: signedRequest() };
  const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: () => twoStep() } });
  await openRequest(h);
  assertSubmitOffered(h, "no anchor");
  await clickAndRepaint(h, submitButton(h), "Submit");
  assert.equal(h.posts(SUBMIT_ROUTE).length, 1, "exactly one Submit is posted");
});

test("RC45 R3N-B1 clarification 02: S-02 a SIGNED, never-attempted request whose withdrawal step 1 recorded an anchor still offers Submit next to the second withdrawal step and Verify state; its next-step text offers waiting, the second step or Submit and claims nothing about which will succeed; pressing Submit posts it once and the server's answer decides [RED on 8900cf5: Submit is disabled once an anchor is recorded, and the next step names only the withdrawal]", async (t) => {
  const s = { request: anchored() };
  const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: () => twoStep() } });
  await openRequest(h);
  assert.ok(step2Button(h), "the second withdrawal step is offered (anchor present)");
  assert.ok(verifyButton(h), "Verify state is offered");
  const next = nextText(h);
  assert.match(next, /\bwait/i, `the next step offers waiting (R3, anchor present); it says: ${next}`);
  assert.match(next, /\bsecond step\b|\bstep 2\b/i, `the next step offers the second withdrawal step; it says: ${next}`);
  assert.match(next, /\bsubmit\b/i, `the next step offers Submit (clarification 02 item 1); it says: ${next}`);
  assert.doesNotMatch(next, NO_OUTCOME_CLAIM, `no claim about which will succeed; it says: ${next}`);
  assert.doesNotMatch(next, NEVER_RECOVERED);
  assertSubmitOffered(h, "anchor present");
  await clickAndRepaint(h, submitButton(h), "Submit");
  assert.equal(h.posts(SUBMIT_ROUTE).length, 1, "exactly one Submit is posted; the server's submit read decides");
});

test("RC45 R3N-B1 clarification 02: S-03 after this page saw Submit answered 409 RECORDED_OUTPUT_SPENT (withdrawal TWO_STEP, nothing written), the SIGNED, never-attempted request still offers Submit next to the two-step withdrawal [RED on 8900cf5: Submit is disabled after the TWO_STEP answer]", async (t) => {
  const s = { request: signedRequest() };
  const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: () => twoStep() } });
  await openRequest(h);
  await clickAndRepaint(h, submitButton(h), "Submit");
  assert.ok(step1Button(h), "the two-step withdrawal is offered after the TWO_STEP answer");
  assertSubmitOffered(h, "after the TWO_STEP 409");
});

for (const finding of ["ROOT_INPUT_NOT_LIVE", "INPUT_CONTRADICTED", "INPUT_EXISTENCE_UNPROVEN"]) {
  test(`RC45 R3N-B1 clarification 02: S-04 after this page saw Submit answered 409 SUBMIT_INPUT_UNRESOLVED (${finding}, nothing written), the SIGNED, never-attempted request still offers Submit (every SIGNED, never-attempted request; the server's submit read decides) ${finding === "INPUT_EXISTENCE_UNPROVEN" ? "[PIN: holds on 8900cf5]" : "[RED on 8900cf5: Submit is disabled after this Submit answer]"}`, async (t) => {
    const s = { request: signedRequest() };
    const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: () => submitUnresolved(finding) } });
    await openRequest(h);
    await clickAndRepaint(h, submitButton(h), "Submit");
    assert.ok(verifyButton(h), "Verify state is offered after this Submit answer");
    assertSubmitOffered(h, `after SUBMIT_INPUT_UNRESOLVED ${finding}`);
  });
}

for (const finding of ["ROOT_INPUT_NOT_LIVE", "ACCEPTED_IN_WINDOW", "IN_TRANSACTION_POOL", "UNSTABLE"]) {
  test(`RC45 R3N-B1 clarification 02: S-05 an anchored request whose second withdrawal step is answered CANNOT_REJECT ${finding} (nothing written) offers Submit, and its next-step text points to Submit, then Verify state — never a success claim, never 'withdrawn' [RED on 8900cf5: Submit stays disabled and the next step still names only the withdrawal]`, async (t) => {
    const s = { request: anchored() };
    const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${REJECT_ROUTE}`]: () => cannotReject(finding) } });
    await openRequest(h);
    await clickAndRepaint(h, step2Button(h), "Withdraw (second step)");
    assert.equal(h.posts(REJECT_ROUTE).length, 1, "the withdrawal was posted once; nothing is retried");
    assert.match(visible(h.notice()), /cannot be withdrawn now/i, "the CANNOT_REJECT answer is shown");
    assertSubmitOffered(h, `after CANNOT_REJECT ${finding}`);
    const next = nextText(h);
    assert.match(next, SUBMIT_THEN_VERIFY, `the next step points to Submit, then Verify state; it says: ${next}`);
    assert.doesNotMatch(next, NO_OUTCOME_CLAIM, `no claim about which will succeed; it says: ${next}`);
    assert.doesNotMatch(next, /\bwithdrawn\b/i, "the request is not described as withdrawn");
    assert.doesNotMatch(next, NEVER_RECOVERED);
  });
}

for (const [label, request] of [["an anchored request", () => anchored()], ["a request whose Submit this page saw answered TWO_STEP (no anchor)", null]]) {
  test(`RC45 R3N-B1 clarification 02: S-06 ${label}: after Verify state answers UNKNOWN SUBMIT_TO_RECORD naming this request (its own transaction is already on the chain), Submit is offered and the next-step text points to Submit, then Verify state; the Verify answer itself says to press Submit on that request [RED on 8900cf5: Submit stays disabled after the Verify answer]`, async (t) => {
    const s = { request: request ? request() : signedRequest() };
    const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: () => twoStep(), [`POST ${RECONCILE_ROUTE}`]: () => submitToRecord() } });
    await openRequest(h);
    if (!request) await clickAndRepaint(h, submitButton(h), "Submit (answered TWO_STEP)");
    await clickAndRepaint(h, verifyButton(h), "Verify state");
    assert.equal(h.posts(RECONCILE_ROUTE).length, 1, "Verify state was posted once");
    const said = visible(h.notice());
    assert.match(said, /Press Submit on that request, then Verify state/, `the Verify answer names the request and says to press Submit on it; it says: ${said}`);
    assert.ok(said.includes(REQ_ID), "the Verify answer names this request");
    assertSubmitOffered(h, "after SUBMIT_TO_RECORD naming this request");
    const next = nextText(h);
    assert.match(next, SUBMIT_THEN_VERIFY, `the next step points to Submit, then Verify state; it says: ${next}`);
    assert.doesNotMatch(next, NO_OUTCOME_CLAIM);
    assert.doesNotMatch(next, NO_REBUILD, "never a build, rebuild or replacement");
  });
}

test("RC45 R3N-B1 clarification 02: S-07 while a withdrawal is pending (step 1 answered 409 WITHDRAWAL_DEPTH_PENDING and wrote the anchor), the request offers waiting, the second step or Submit: Submit and the second step are offered, the next-step text names all three and claims nothing about which will succeed, and the answer shows the DAA window without calling the request withdrawn [RED on 8900cf5: Submit is disabled while the withdrawal is pending]", async (t) => {
  const s = { request: signedRequest() };
  const h = await loadPage(t, { routes: {
    [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }),
    [`POST ${SUBMIT_ROUTE}`]: () => twoStep(),
    [`POST ${REJECT_ROUTE}`]: () => { s.request = anchored(); return depthPending(); } // step 1 writes only the anchor
  } });
  await openRequest(h);
  await clickAndRepaint(h, submitButton(h), "Submit (answered TWO_STEP)");
  await clickAndRepaint(h, step1Button(h), "Withdraw (step 1)");
  assert.ok(h.confirms.some((c) => c.includes(OWNER_SENTENCE)), "the step-1 confirmation carries the owner's sentence");
  const said = visible(h.notice());
  assert.match(said, new RegExp(`from DAA ${ANCHOR_DAA + 1000n} to DAA ${ANCHOR_DAA + 12000n}`), `the pending answer shows the DAA window; it says: ${said}`);
  assert.doesNotMatch(said, /\bRequest withdrawn\b|reservation is released/i, "the pending answer never calls the request withdrawn");
  assert.doesNotMatch(said, NO_OUTCOME_CLAIM, "the pending answer claims nothing about which step will succeed");
  assert.ok(step2Button(h), "the second step is offered");
  assertSubmitOffered(h, "withdrawal pending");
  const next = nextText(h);
  assert.match(next, /\bwait/i, `the next step offers waiting; it says: ${next}`);
  assert.match(next, /\bsecond step\b|\bstep 2\b/i, `the next step offers the second step; it says: ${next}`);
  assert.match(next, /\bsubmit\b/i, `the next step offers Submit; it says: ${next}`);
  assert.doesNotMatch(next, NO_OUTCOME_CLAIM, `no claim about which will succeed; it says: ${next}`);
});

/* ============================== item 2: app-v4's R4 answer wiring (behavioural; C4-06 check F02) ============================== */
test("RC45 R3N-B1 clarification 02: W-01 (R4 wiring; catches X19) Submit answered 409 RECORDED_OUTPUT_SPENT with withdrawal TWO_STEP is recorded by the page: the two-step withdrawal (step 1) is offered with the owner's sentence, Verify state is offered, no build, rebuild or replacement is offered, the answer reads 'Submit refused — nothing was recorded or sent', nothing is retried, and confirming step 1 shows T-B1 and posts the withdrawal once [PIN: holds on 8900cf5]", async (t) => {
  const s = { request: signedRequest() };
  const h = await loadPage(t, { routes: {
    [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }),
    [`POST ${SUBMIT_ROUTE}`]: () => twoStep(),
    [`POST ${REJECT_ROUTE}`]: () => { s.request = anchored(); return depthPending(); }
  } });
  await openRequest(h);
  assert.equal(step1Button(h), null, "no withdrawal is offered before the answer (a plain SIGNED request is resumed by Submit)");
  await clickAndRepaint(h, submitButton(h), "Submit");
  assert.equal(h.posts(SUBMIT_ROUTE).length, 1, "one Submit; never retried automatically");
  assert.match(visible(h.notice()), /Submit refused — nothing was recorded or sent/, `the structured TWO_STEP refusal; the notice says: ${visible(h.notice()).slice(0, 400)}`);
  const step1 = step1Button(h);
  assert.ok(step1, "the TWO_STEP answer is recorded: the two-step withdrawal (step 1) is offered");
  assert.ok(String(step1.getAttribute("title")).includes(OWNER_SENTENCE), "the offer carries the owner's sentence verbatim");
  assert.ok(verifyButton(h), "Verify state is offered");
  assert.doesNotMatch(visible(h.card()), NO_REBUILD, "no build, rebuild or replacement next to this answer");
  await clickAndRepaint(h, step1, "Withdraw (step 1)");
  const confirm = h.confirms.join(" ");
  assert.ok(confirm.includes(OWNER_SENTENCE) && /final at 1,000 DAA/.test(confirm), `the step-1 confirmation carries T-B1; it says: ${confirm.slice(0, 600)}`);
  assert.equal(h.posts(REJECT_ROUTE).length, 1, "the withdrawal step is posted once");
});

const UNCERTAIN = /outcome uncertain|outcome (?:is )?unknown/i;
for (const [label, answer] of [
  ["the connection is lost after the request was sent (the server may have broadcast)", () => ({ transportLoss: true })],
  ["the gateway answers 502 with a body that is not JSON", () => ({ noJson: 502 })],
  ["the server answers 500 with a code that has no closed explanation", () => err(500, "SUBMIT_BROADCAST_UNCONFIRMED", "wallet-requests-v7: the broadcast's outcome could not be confirmed")]
]) {
  test(`RC45 R3N-B1 clarification 02: W-02 (R4 wiring; catches X18) when ${label}, the Submit failure is shown as an uncertain outcome with Verify state — never 'nothing was recorded or sent', never 'Submit refused' — and nothing is retried [PIN: holds on 8900cf5]`, async (t) => {
    const s = { request: signedRequest() };
    const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: answer } });
    await openRequest(h);
    await clickAndRepaint(h, submitButton(h), "Submit");
    const said = visible(h.notice());
    assert.match(said, UNCERTAIN, `the failure is an uncertain outcome; the notice says: ${said.slice(0, 400)}`);
    assert.match(said, /Verify state/, "it points to Verify state");
    assert.doesNotMatch(said, NOTHING_SENT, "never 'nothing was recorded or sent' for this failure");
    assert.doesNotMatch(said, /Submit refused/, "never presented as a refusal of the submit read");
    assert.equal(h.posts(SUBMIT_ROUTE).length, 1, "nothing is retried");
    assert.equal(step1Button(h), null, "no withdrawal is offered on an uncertain Submit outcome");
  });
}

test("RC45 R3N-B1 clarification 02: W-03 (R4 wiring; catches X18) a 409 RECORDED_OUTPUT_SPENT that carries no structured submitRead is not presented as the submit read's refusal: never 'nothing was recorded or sent', and no withdrawal is offered [PIN: holds on 8900cf5]", async (t) => {
  const s = { request: signedRequest() };
  const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${SUBMIT_ROUTE}`]: () => err(409, "RECORDED_OUTPUT_SPENT", "wallet-requests-v7: the recorded treasury output is not reported unspent") } });
  await openRequest(h);
  await clickAndRepaint(h, submitButton(h), "Submit");
  const said = visible(h.notice());
  assert.ok(said.includes("RECORDED_OUTPUT_SPENT"), `the code is shown; the notice says: ${said.slice(0, 400)}`);
  assert.doesNotMatch(said, NOTHING_SENT, "never 'nothing was recorded or sent' without the structured refusal");
  assert.equal(step1Button(h), null, "no withdrawal is offered without the structured TWO_STEP answer");
});

for (const [finding, meaning] of [["INPUTS_LIVE", /reported unspent again/i], ["OWN_OUTPUT", /own transaction/i]]) {
  test(`RC45 R3N-B1 clarification 02: W-04 (R4 wiring; catches X20) an anchored request whose second withdrawal step is answered CANNOT_REJECT ${finding} shows that finding: the next-step text changes from the anchored offer to the finding's meaning and points to Submit, then Verify state; Submit is offered; the answer's explanation names the finding's next step; nothing is retried [PIN: holds on 8900cf5]`, async (t) => {
    const s = { request: anchored() };
    const h = await loadPage(t, { routes: { [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }), [`POST ${REJECT_ROUTE}`]: () => cannotReject(finding) } });
    await openRequest(h);
    const before = nextText(h);
    await clickAndRepaint(h, step2Button(h), "Withdraw (second step)");
    const next = nextText(h);
    assert.notEqual(next, before, `the next step changes with the finding (before: ${before})`);
    assert.match(next, meaning, `the next step states the ${finding} finding's meaning; it says: ${next}`);
    assert.match(next, SUBMIT_THEN_VERIFY, `it points to Submit, then Verify state; it says: ${next}`);
    assertSubmitOffered(h, `after CANNOT_REJECT ${finding}`);
    assert.match(visible(h.notice()), meaning, "the answer's explanation names the finding's next step");
    assert.equal(h.posts(REJECT_ROUTE).length, 1, "nothing is retried");
  });
}

test("RC45 R3N-B1 clarification 02: W-05 (R4 wiring; catches X15) a REFUSED request withdrawn by the input-spent withdrawal (W8) whose root, re-read when the modal opens, still names it is offered 'Finish withdrawal' and Verify state, never Submit; confirming says nothing is broadcast and posts the withdrawal once; once the root's pointer is cleared no finish is offered [PIN: holds on 8900cf5]", async (t) => {
  let pointer = REQ_ID;
  const s = { request: withdrawnW8() };
  const h = await loadPage(t, {
    root: () => rootRecord(pointer),
    routes: {
      [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }),
      [`POST ${REJECT_ROUTE}`]: () => { pointer = null; return { body: { request: s.request } }; }
    }
  });
  await openRequest(h);
  const finish = finishButton(h);
  assert.ok(finish, `'Finish withdrawal' is offered while the root still names this REFUSED request (modal: ${visible(h.card()).slice(0, 500)})`);
  assert.match(visible(finish), /Finish withdrawal/);
  assert.ok(verifyButton(h), "Verify state is offered next to it");
  const sub = submitButton(h);
  assert.ok(!sub || sub.disabled, "Submit is never offered for a REFUSED request");
  finish.click();
  assert.ok(await until(() => h.posts(REJECT_ROUTE).length === 1), "the finish is posted");
  await pause(50);
  assert.equal(h.posts(REJECT_ROUTE).length, 1, "posted exactly once");
  assert.ok(h.confirms.some((c) => /Finish withdrawal\?/.test(c) && /Nothing is broadcast/.test(c)), `the finish confirmation says nothing is broadcast (${h.confirms.join(" | ").slice(0, 400)})`);
});

/* ============================== item 3: the unreadable root (C4-06 check F03) ============================== */
for (const [rootLabel, failing] of [
  ["the root re-read fails (503)", () => err(503, "STORE_UNAVAILABLE", "the root record could not be read")],
  ["the root re-read answers without a root record", () => ({ body: {} })]
]) {
  for (const [reqLabel, request] of [["withdrawn by the input-spent withdrawal (W8)", withdrawnW8], ["withdrawn while carrying owner signatures (the stale withdrawal)", () => signedRequest({ state: "REFUSED", error: "withdrawn by an owner", finalizedTxHex: undefined, finalTransaction: undefined })]]) {
    test(`RC45 R3N-B1 clarification 02: R-01 a REFUSED request ${reqLabel} whose root cannot be re-read when the modal opens (${rootLabel}) claims nothing about the reservation: it states that the reservation could not be confirmed, offers Verify state (which posts the root's Verify), and never says that the root is no longer reserved [RED on 8900cf5: an unreadable root is read as a cleared pointer ('this request no longer reserves the root')]`, async (t) => {
      const s = { request: request() };
      const h = await loadPage(t, {
        root: () => rootRecord(REQ_ID),
        routes: {
          [`GET /org-roots/${ROOT_ID}`]: (_, n) => (n === 1 ? { body: { orgRoot: rootRecord(REQ_ID) } } : failing()), // the root detail read it; the modal's re-read cannot
          [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } }),
          [`POST ${RECONCILE_ROUTE}`]: () => ({ body: { reconcile: { root: { status: "CONSISTENT", rootCovenantId: ROOT_ID }, vaults: [] } } })
        }
      });
      await openRequest(h);
      const said = visible(h.card());
      assert.doesNotMatch(said, RELEASED_CLAIM, `never says the root is no longer reserved; the modal says: ${said.slice(0, 900)}`);
      assert.match(said, NOT_CONFIRMED, `states that the reservation could not be confirmed; the modal says: ${said.slice(0, 900)}`);
      const verify = verifyButton(h);
      assert.ok(verify, "Verify state is offered");
      verify.click();
      assert.ok(await until(() => h.posts(RECONCILE_ROUTE).length === 1), "Verify state posts the root's Verify");
      await pause(50);
    });
  }
}

test("RC45 R3N-B1 clarification 02: R-02 (control for R-01) a REFUSED W8 request whose root, re-read when the modal opens, no longer names it offers no 'Finish withdrawal' and does not say the reservation could not be confirmed [PIN: holds on 8900cf5]", async (t) => {
  const s = { request: withdrawnW8() };
  const h = await loadPage(t, {
    root: () => rootRecord(REQ_ID),
    routes: {
      [`GET /org-roots/${ROOT_ID}`]: (_, n) => ({ body: { orgRoot: rootRecord(n === 1 ? REQ_ID : null) } }), // cleared between the root detail and the modal
      [`GET ${REQ_ROUTE}`]: () => ({ body: { request: s.request } })
    }
  });
  await openRequest(h);
  assert.equal(finishButton(h), null, "no finish once the pointer is cleared (R3: REFUSED, pointer cleared: nothing)");
  assert.doesNotMatch(visible(h.card()), NOT_CONFIRMED, "a readable root is not reported as unconfirmed");
});
