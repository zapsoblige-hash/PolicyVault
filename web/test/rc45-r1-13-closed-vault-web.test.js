"use strict";

/*
 * RC45 R1-13 (O1) — THE CLOSED VERIFY MAP TELLS A CLOSED VAULT'S
 * REQUEST_RECOVERY_REQUIRED AS A WRITE WHEN VERIFY SETTLED SOMETHING (design
 * amendment PA-R1-02 "R1-13", independent design check condition C1).
 * Internal RED-first regression material for the RC45 successor candidate;
 * not an audit. The candidate-written answers (SDK, the hosted route and the
 * real route body through this map) are in
 * sdk/test/rc45-r1-13-closed-vault-settled.test.js.
 *
 * The rule (C1): in web/refusal-explain.js verifyStatus, REQUEST_RECOVERY_REQUIRED
 * with recordedVaultClosed === true may say "nothing was written" only when
 * settled[] is absent or empty. When settled[] is non-empty its entries are
 * listed under their existing labels (listSettled, "Completed by this Verify"
 * for CHAIN_VERIFIED). The closed-vault notice ("closed vault, history only")
 * and pending[] stay. Sabotage row: the closed-vault line always says
 * "nothing was written".
 *
 * RED on ecb9928: the recorded-closed line is unconditional
 * (web/refusal-explain.js :785-786), so a closed vault whose Verify completed a
 * record is told "nothing was written" next to "Completed by this Verify".
 * HOLDS on ecb9928 (and must keep holding): with settled[] absent or empty the
 * closed line, including "nothing was written", is exactly as today; a live
 * vault's REQUEST_RECOVERY_REQUIRED is unchanged.
 *
 * Answer shapes: exactly the fields sdk/src/reconcile-v4.js step 3 returns
 * (status, vaultId, requestId, pending[], vaultStatus, recordedVaultClosed,
 * reason) plus the existing settled[] field in the form settleLive already
 * uses; entries in reconcile-v4.js entryOf / pendingEntry shape. Step 3 can
 * only complete records (finishRecordedV4: completeRecord and twinComplete),
 * so its settled[] entries are CHAIN_VERIFIED.
 *
 * Layer: MAP (the real web/refusal-explain.js verifyStatus and
 * renderVerifyHtml). A RECOVERED card offers no Verify control in
 * web/app-v4.js (read-only history), so there is no browser leg; the map is
 * what every web surface renders a Verify answer through.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const RX = require("../refusal-explain.js");

const HEX = (s) => s.repeat(32);
const VAULT_ID = HEX("7c");
const CLOSED_REASON = "the recorded vault is closed; historical request evidence remains unresolved and protected; no new recovery or transaction is authorized";
const CLOSED_LINE = "The vault is recorded as closed (closed vault, history only): historical signed work remains unresolved and protected; nothing was written and no new transaction is authorized.";
const NOTHING_WRITTEN = /nothing was written/i;
const PENDING = Object.freeze({ requestId: "0f8a1301-0000-4000-8000-000000001301", action: "ownerPause", state: "PREFLIGHT_VERIFIED", txId: HEX("a1"), signerRole: "owner" });
const DONE = Object.freeze({ requestId: "0f8a1302-0000-4000-8000-000000001302", action: "agentSpend", state: "CHAIN_VERIFIED", txId: HEX("a2") });
const TWIN = Object.freeze({ requestId: "0f8a1303-0000-4000-8000-000000001303", action: "agentSpend", state: "CHAIN_VERIFIED", txId: HEX("a2") });

function closedAnswer(extra = {}) {
  return { status: "REQUEST_RECOVERY_REQUIRED", vaultId: VAULT_ID, requestId: PENDING.requestId, pending: [{ ...PENDING }], vaultStatus: "RECOVERED", recordedVaultClosed: true, reason: CLOSED_REASON, ...extra };
}
/* The map shows ids shortened to their first 8 and last 6 characters (refusal-explain.js short()). */
const shortId = (id) => `${id.slice(0, 8)}\u2026${id.slice(-6)}`;
const listed = (line, entry) => line.includes(shortId(entry.requestId)) && line.includes(shortId(entry.txId));
const htmlText = (html) => html.replace(/<[^>]+>/g, " ").replace(/&[a-z]+;/g, " ").replace(/\s+/g, " ");
/* The server's own reason is rendered verbatim beside the map's lines; it never says "nothing was written" here. */
function assertTold(v, settled, where) {
  const text = v.lines.join(" ");
  assert.equal(v.known, true); assert.equal(v.level, "warn", `${where}: REQUEST_RECOVERY_REQUIRED stays warn`);
  assert.equal(v.title, "Signed work on this vault is still unresolved");
  assert.ok(text.includes("closed vault, history only"), `${where}: the closed-vault notice stays; it says: ${text}`);
  assert.ok(text.includes("no new transaction is authorized"), `${where}: no new transaction is authorized; it says: ${text}`);
  assert.ok(v.lines.some((l) => l.startsWith("Pending:") && listed(l, PENDING)), `${where}: the pending record stays listed; it says: ${text}`);
  const completed = v.lines.filter((l) => l.startsWith("Completed by this Verify:"));
  assert.equal(completed.length, 1, `${where}: one "Completed by this Verify" line; it says: ${text}`);
  for (const e of settled) assert.ok(listed(completed[0], e), `${where}: ${e.requestId} is listed under "Completed by this Verify"; it says: ${text}`);
  assert.ok(v.lines.every((l) => !NOTHING_WRITTEN.test(l)), `${where}: a Verify that settled something is never told "nothing was written" (C1); it says: ${text}`);
}

/* ---------------- RED: settled[] non-empty on a recorded-closed vault ---------------- */
test("RC45 R1-13 map: a recorded-closed REQUEST_RECOVERY_REQUIRED whose Verify completed one record (settled[] = [CHAIN_VERIFIED]) lists it under \"Completed by this Verify\", keeps the closed-vault notice and pending[], and never says \"nothing was written\" [RED on ecb9928]", () => {
  assertTold(RX.verifyStatus(closedAnswer({ settled: [{ ...DONE }] })), [DONE], "one completed record");
});
test("RC45 R1-13 map: a recorded-closed REQUEST_RECOVERY_REQUIRED whose Verify completed a record and its signed same-txid twin lists both under \"Completed by this Verify\" and never says \"nothing was written\" [RED on ecb9928]", () => {
  assertTold(RX.verifyStatus(closedAnswer({ settled: [{ ...DONE }, { ...TWIN }] })), [DONE, TWIN], "a record and its twin");
});
test("RC45 R1-13 map: renderVerifyHtml of a recorded-closed REQUEST_RECOVERY_REQUIRED with settled[] (the block every web surface shows) keeps the raw token and the server's reason, lists the completed record, and never says \"nothing was written\" [RED on ecb9928]", () => {
  const text = htmlText(RX.renderVerifyHtml(closedAnswer({ settled: [{ ...DONE }] })));
  assert.ok(text.includes("REQUEST_RECOVERY_REQUIRED"), `the raw token stays visible; it says: ${text}`);
  assert.ok(text.includes(CLOSED_REASON), `the server's own reason stays visible; it says: ${text}`);
  assert.ok(text.includes("Completed by this Verify:") && text.includes(DONE.requestId.slice(0, 8)), `the completed record is listed; it says: ${text}`);
  assert.doesNotMatch(text, NOTHING_WRITTEN, `the block never says "nothing was written" after a write (C1); it says: ${text}`);
});

/* ---------------- HOLDS: settled[] absent or empty ---------------- */
for (const [label, extra] of [["absent", {}], ["empty", { settled: [] }]]) {
  test(`RC45 R1-13 map (holds): a recorded-closed REQUEST_RECOVERY_REQUIRED with settled[] ${label} keeps today's closed-vault line exactly, including "nothing was written", lists pending[] and lists nothing as completed`, () => {
    const v = RX.verifyStatus(closedAnswer(extra)), text = v.lines.join(" ");
    assert.equal(v.level, "warn");
    assert.ok(v.lines.includes(CLOSED_LINE), `the closed-vault line is exactly as today; it says: ${text}`);
    assert.ok(v.lines.some((l) => l.startsWith("Pending:") && listed(l, PENDING)), `pending[] is listed; it says: ${text}`);
    assert.ok(v.lines.every((l) => !l.startsWith("Completed by this Verify:")), `nothing is listed as completed; it says: ${text}`);
  });
}
test("RC45 R1-13 map (holds): a LIVE vault's REQUEST_RECOVERY_REQUIRED (recordedVaultClosed false) with settled[] is unchanged: the signed-work lines, pending[] and the completed entry, and no closed-vault notice", () => {
  const v = RX.verifyStatus({ ...closedAnswer({ settled: [{ ...DONE }] }), vaultStatus: "ACTIVE", recordedVaultClosed: false, reason: "signed work on the recorded outpoint may still execute and blocks other actions" });
  const text = v.lines.join(" ");
  assert.ok(text.includes("Signed work may still execute and blocks other actions"), `it says: ${text}`);
  assert.ok(!text.includes("closed vault, history only"), `no closed-vault notice on a live vault; it says: ${text}`);
  assert.ok(v.lines.some((l) => l.startsWith("Completed by this Verify:") && listed(l, DONE)), `it says: ${text}`);
  assert.ok(v.lines.some((l) => l.startsWith("Pending:") && listed(l, PENDING)), `it says: ${text}`);
});
