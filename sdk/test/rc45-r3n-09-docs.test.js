"use strict";
/*
 * RC45 L2-01 C4-07 — THE DOCUMENTATION OF THE NARROWED C + GUARD REPAIR AND OF R3N-B1. Internal RED-first regression
 * material for the RC45 candidate; not an external engagement of any kind.
 *
 * REQUIRED TEXT (contract revision 2 §6 item 7 with addendum v2a item 6, contract-03 revision 3 §9 with writer
 * amendment A1, the writer decision on the wording after the PARTIAL upgrade items 2-4, and the carried disclosures):
 *   - docs/postlaunch/lead5-reconciliation-remediation.md §10: the status label in its only permitted form (writer
 *     decision item 2 applied); the disposition table with the rows L2-01, GAP-2, GAP-2b (R3N-B1 approved), GAP-3,
 *     GAP-16, GAP-18, GAP-6 and GAP-9 (never the not-approved GAP-2b row); the GAP-2 row and the upgrade depth
 *     statement (items 3 and 4); the GAP-2b residuals r1-r15 with their assumptions, r3 with its pre-activation
 *     control, r9, and r13(d″) verbatim from amendment A1; GAP-6 and GAP-9 separate, unresolved and not accepted; the
 *     carried disclosures (K1' node wait, another root's identifiers in a refusal, the summary routes failing closed,
 *     the upgrade's history line, a reversed upgrade's fields);
 *   - docs/postlaunch/v0.7-app-surface-contract.md §2.2: the attribution answer (every served UNKNOWN outcome the
 *     runtime can give), the holds and buildability, the UNRESOLVED treasury with the served explanation, the
 *     build-time guard (exactly what it prevents and does not prevent), R3N-B1 (the submit read, the own-transaction
 *     distinction, the two-step withdrawal with every CANNOT_REJECT finding the runtime gives, the existence evidence
 *     including E1s, the constants as the runtime defines them), the served withdrawal texts (the owner's sentence
 *     verbatim) and the codes with their statuses;
 *   - statements the repair made false are corrected (the reject row's "terminal REFUSED", the finalized-request
 *     sentences of both documents, the rollback section's first sentence);
 *   - (holds) the six passages the public copy quotes from the remediation record stay verbatim;
 *   - the new sections never use the word for an external engagement, never say the changed treasury was recovered or
 *     that the root and treasury recovered completely, and never describe B-1 as fixed.
 *
 * C4-07a CORRECTIONS (the C4-07 independent item check, findings C407-CHK-F01, F02, F03 and F05; writer clarification 03
 * to contract-03 for F01):
 *   - DOC-15 (F01): r13(d″)'s hold sentence is clarification 03's binding replacement, verbatim; amendment A1's earlier
 *     sentence ("after which C4-03 settlement settles the request") is false at runtime (B1-05c: after the owners' exit,
 *     an unrecorded spend of P, Verify answers UNKNOWN NO_CANDIDATE and writes nothing) and appears in no document; the
 *     GAP-2 row says the same about the exit;
 *   - DOC-16 (F02): the agent API spec no longer says a finalized root request is "not refused at submit (neither can be
 *     withdrawn)"; it states the submit read's 409 RECORDED_OUTPUT_SPENT with nothing written and the two-step
 *     withdrawal, as §2.2.5 does;
 *   - DOC-17 (F03): §2.2 states the wire convention for a refusal's additional fields (top-level members of the HTTP
 *     error envelope; `extra.*` only in the SDK), and it matches server/src/server.js and sdk/src/http-client.js;
 *   - DOC-18 (F05 a-e): the five wording corrections (the pointer save never refuses; text S excepts the input-spent
 *     withdrawal; only the treasury output is read twice in the upgrade; the build's OBSERVATION_ERROR also covers an
 *     anchor that left the selected chain by its recheck; §10.1 states the existence-evidence condition).
 *
 * Layer: UNIT (static reads of checked-in documents and runtime sources). No store, no node.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const norm = (s) => String(s).replace(/\s+/g, " ").trim();
const LEAD5 = "docs/postlaunch/lead5-reconciliation-remediation.md";
const SURFACE = "docs/postlaunch/v0.7-app-surface-contract.md";
const WR7 = "sdk/src/wallet-requests-v7.js";

/* lead5 §10, from its heading to the end of the document (or the next "## " heading) */
function lead5Section10() {
  const text = read(LEAD5);
  const a = text.indexOf("\n## 10. Organization roots: a root move broadcast outside PolicyVault (L2-01)\n");
  assert.ok(a >= 0, "lead5 has the section \"## 10. Organization roots: a root move broadcast outside PolicyVault (L2-01)\"");
  const rest = text.slice(a + 1);
  const next = rest.indexOf("\n## ", 3);
  return next < 0 ? rest : rest.slice(0, next + 1);
}
/* the app-surface contract's §2.2, from its heading up to "## 3." */
function surfaceSection22() {
  const text = read(SURFACE);
  const a = text.indexOf("\n### 2.2 Root moves broadcast outside PolicyVault, the build-time guard and spent inputs");
  assert.ok(a >= 0, "the app-surface contract has the section \"### 2.2 Root moves broadcast outside PolicyVault, the build-time guard and spent inputs\"");
  const b = text.indexOf("\n## 3. ", a);
  assert.ok(b > a, "§2.2 ends before \"## 3.\"");
  return text.slice(a + 1, b + 1);
}
/* the markdown table rows (cells trimmed) that follow a header row whose first cell is `firstHeader` */
function tableRows(section, firstHeader) {
  const lines = section.split("\n");
  const h = lines.findIndex((l) => l.startsWith(`| ${firstHeader} |`));
  assert.ok(h >= 0, `a table headed "${firstHeader}" is present`);
  const rows = [];
  const cells = (line) => line.split("|").slice(1, -1).map((c) => c.trim()); // no cell of these tables contains "|"
  for (let i = h + 2; i < lines.length && lines[i].startsWith("|"); i += 1) rows.push(cells(lines[i]));
  return { header: cells(lines[h]), rows };
}

/* The status label: contract revision 2's only permitted form with the writer decision's item 2 applied. */
const LABEL = "L2-01: Narrowed C + guard implemented. From the first Verify at ≥ 1,000 DAA after an attributable case-5 broadcast, the root and its unaffected treasuries regain hosted actions, FREEZE included, once no stranded request still holds them; that Verify names any that does. Not a complete root-and-treasury recovery: the changed treasury stays UNRESOLVED when it moved outside PolicyVault (GAP-2); a later Verify restores it only when that treasury's expected output is observed unspent again; GAP-2b, GAP-3 and GAP-16 remain as stated in the disposition table; the late-broadcast funds exposure (GAP-6) and the pre-activation check omission (GAP-9) are unresolved and not accepted.";

/* writer clarification 03 to contract-03 (C407-CHK-F01): the binding replacement of amendment A1's r13(d″) hold-ends
 * sentence, verbatim; it replaces that sentence everywhere it is quoted */
const R13D2_HOLD = "In the hosted record this hold does not end. The owners' direct on-chain exit moves the root outside PolicyVault (GAP-1): Verify then answers UNKNOWN and writes nothing; no settlement runs.";
/* amendment A1's replaced sentence, false at runtime (B1-05c); it must appear in no document */
const R13D2_HOLD_FALSE = "**The hold ends** only through an out-of-app root transition: the on-chain exit, after which C4-03 settlement settles the request.";

/* r13(d″), verbatim from writer amendment A1 ("The remaining corner, stated precisely") with its hold-ends sentence
 * replaced by clarification 03's binding text (C4-07a), one entry per source line */
const R13D2 = [
  "A permanent root-wide hold, FREEZE included, remains for a finalized, never-attempted root request only when **all** of the following hold:",
  "1. A non-root input was under 1,000 DAA deep at build.",
  "2. Its creating transaction is not P's (a cross-root fee change, an explicit fresh fee input, or a treasury output created by a delegate payment).",
  "3. Another party spends it before Submit.",
  "4. No PolicyVault save of the request (slot request, slot signature or finalize) happened between about 100 s after the build and the end of the node's retention, which is at least about 30 h.",
  "5. Withdraw step 1 first runs after that retention ended.",
  R13D2_HOLD,
  "**Proposed rating:** LOW. A Submit answers 409 synchronously and offers Withdraw, which works at any time within retention. The corner needs every PolicyVault save to be under 100 s after the build, and then no withdrawal attempt for at least 30 h.",
  "**The independent R3N-B1 check rates it.** If it is rated MEDIUM, it stays a release blocker, and the owner decides between K2′, K4 and acceptance.",
  "**B-1 is not described as fixed for this corner.**"
];

const OWNER_SENTENCE = "Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast.";
const TEXT_S = "Withdrawing marks this request withdrawn in PolicyVault and releases the root's reservation. It does not revoke the owner signatures already given: anyone holding them and the fee-input signature can still broadcast this exact transaction outside PolicyVault while the outputs it spends are unspent. Withdrawing broadcasts nothing.";
const T_B1 = "Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast. PolicyVault withdraws this finalized request only because the <role> output it spends was spent by another transaction, and that spend is final at 1,000 DAA. This request's transaction can therefore no longer be accepted unless the network reverses more than 1,000 DAA of its history; if that happened and the transaction were broadcast outside PolicyVault, PolicyVault would not recognize it as this request. Withdrawing marks this request withdrawn in PolicyVault and releases the root's reservation. It broadcasts nothing.";
const HOLD_CLAUSE = "holds the root until it is withdrawn (two steps, at least 1,000 DAA apart), or longer in the disclosed cases where a withdrawal cannot be proven safe";
const UNRESOLVED_EXPLANATION = "PolicyVault cannot confirm this treasury's current state: its expected output was spent outside PolicyVault after an out-of-band change to its delegate rules. Hosted actions on this treasury stay closed. A later Verify restores them only if it finds that expected output unspent again (for example after a reorganization); otherwise only the owners' direct on-chain exit can act on it.";

test("RC45 C4-07 DOC-01: lead5 §10 carries the L2-01 status label in its only permitted form (writer decision item 2 applied) exactly once, and the record's status section points to it [RED on 007d739]", () => {
  const section = norm(lead5Section10());
  assert.ok(section.includes(`**Status label (the only permitted form):** ${LABEL}`), "§10 states the label verbatim under its heading");
  assert.equal(norm(read(LEAD5)).split(LABEL).length - 1, 1, "the label appears exactly once in the record");
  assert.equal(norm(read(LEAD5)).includes("also if a reorg later reverses that move"), false, "the superseded GAP-2 clause is gone");
  const status = norm(read(LEAD5).split("\n## 1.")[0]);
  assert.ok(status.includes("**Organization roots (L2-01, §10):** IMPLEMENTED and UNIT-TESTED") && status.includes("Not TESTNET-VERIFIED"), "the status section states the L2-01 claim labels and points to §10");
});

test("RC45 C4-07 DOC-02: lead5 §10.2's disposition table has exactly the rows L2-01, GAP-2, GAP-2b (R3N-B1 approved), GAP-3, GAP-16, GAP-18, GAP-6 and GAP-9 with six columns each; GAP-6 and GAP-9 stay separate, unresolved and not accepted; no not-approved GAP-2b row [RED on 007d739]", () => {
  const section = lead5Section10();
  const { header, rows } = tableRows(section, "Item");
  assert.deepEqual(header.slice(0, 3), ["Item", "Origin", "Consequence"], "the table's first columns");
  assert.equal(header.length, 6, "six columns: item, origin, consequence, severity, coverage, unresolved");
  assert.deepEqual(rows.map((r) => r[0]), ["L2-01", "GAP-2", "GAP-2b (R3N-B1 approved)", "GAP-3", "GAP-16", "GAP-18", "GAP-6", "GAP-9"], "the disposition rows, in order");
  for (const r of rows) assert.equal(r.length, 6, `row ${r[0]} has six cells`);
  const row = (id) => rows.find((r) => r[0] === id);
  for (const id of ["GAP-6", "GAP-9"]) {
    assert.equal(row(id)[3], "Not accepted", `${id} is not accepted`);
    assert.equal(row(id)[5], "Yes, separate", `${id} stays unresolved and separate`);
  }
  assert.ok(row("GAP-6")[2].startsWith("Late-broadcast funds exposure"), "GAP-6 names the late-broadcast funds exposure");
  assert.ok(row("GAP-9")[2].startsWith("The pre-activation check omission"), "GAP-9 names the pre-activation check omission");
  assert.ok(norm(section).includes("GAP-6 and GAP-9 stay separate, unresolved matters: being outside this repair does not make them accepted."), "the record says GAP-6 and GAP-9 stay separate and unresolved");
  for (const rel of [LEAD5, SURFACE]) assert.equal(read(rel).includes("GAP-2b (not approved)"), false, `${rel}: no not-approved GAP-2b row`);
  assert.equal(norm(section).includes("and can hold the root again"), false, "the not-approved FULL-warning clause is not used");
  for (const id of ["L2-01", "GAP-2", "GAP-2b (R3N-B1 approved)", "GAP-3", "GAP-16"]) {
    assert.ok(/Introduced|Pre-existing/.test(row(id)[1]), `${id} states whether it was introduced or pre-existing`);
    assert.ok(row(id)[4].length > 0 && row(id)[5].length > 0, `${id} states its coverage and what remains unresolved`);
  }
  assert.ok(row("GAP-2b (R3N-B1 approved)")[1].includes("not worsened") && row("GAP-2")[1].includes("not worsened"), "GAP-2 and GAP-2b are stated not worsened");
});

test("RC45 C4-07 DOC-03: the GAP-2 row and both documents state the writer decision items 3 and 4 (closed until the expected output is observed unspent again at depth; never restored from stale or spent state; the depth is the age of that output's acceptance, not of a reversal; a restored output spent again is refused RECORDED_OUTPUT_SPENT) [RED on 007d739]", () => {
  const section = lead5Section10();
  const gap2 = tableRows(section, "Item").rows.find((r) => r[0] === "GAP-2");
  assert.ok(gap2[2].includes("Hosted actions on T1 stay closed until a later Verify observes its expected output unspent again at depth; T1 is never restored from stale or spent state"), `the GAP-2 row states item 3; it says: ${gap2[2]}`);
  assert.ok(gap2[2].includes("a root FREEZE does not stop its delegates"), "the GAP-2 row says a root FREEZE does not stop T1's delegates");
  const lead = norm(section), surface = norm(surfaceSection22());
  assert.ok(lead.includes("The depth used is the age of that output's acceptance, not the age of a reversal.") && lead.includes("If a restored output is spent again, T1 is refused `RECORDED_OUTPUT_SPENT` by the build-time guard"), "lead5 states item 4");
  assert.ok(surface.includes("The depth used is the age of the expected output's acceptance, not the age of a reversal") && surface.includes("If a restored output is spent again, T1 is refused `RECORDED_OUTPUT_SPENT` by the build-time guard"), "the app-surface contract states item 4");
  assert.ok(surface.includes("T1 is never restored from stale or spent state."), "the app-surface contract states the never-stale rule");
  assert.ok(surface.includes("only mode FULL with treasury ADVANCED means that T1 follows that output"), "a reversed upgrade's leftover fields are never read as an upgrade");
});

test("RC45 C4-07 DOC-04: lead5 §10.3 states the GAP-2b residuals precisely: r13(d″) verbatim from amendment A1 (its hold-ends sentence as clarification 03 replaces it) and its rating, r1-r15 with the assumptions G5, IX, RD, MG′ and TN, r3 with its pre-activation control kept separate from GAP-9, and r9; the GAP-2b row names them [RED on 007d739]", () => {
  const section = lead5Section10();
  const lines = section.split("\n");
  const at = lines.indexOf("**The remaining corner, stated precisely (r13(d″))**");
  assert.ok(at >= 0, "the r13(d″) block is headed");
  let i = at + 1;
  for (const expected of R13D2) {
    while (i < lines.length && lines[i].trim() === "") i += 1;
    assert.equal(lines[i], expected, "r13(d″) is verbatim from amendment A1 (with clarification 03's hold sentence), line for line");
    i += 1;
  }
  const text = norm(section);
  assert.ok(text.includes("The independent R3N-B1 check rated r13(d″) LOW."), "the check's rating of r13(d″) is stated");
  const { rows } = tableRows(section, "#");
  const ids = rows.map((r) => r[0]);
  for (const id of ["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r13(a)", "r13(b)", "r13(c)", "r13(d″)", "r14", "r15"]) assert.ok(ids.includes(id), `residual ${id} is listed`);
  for (const r of rows) assert.ok(/LOW|Covered by r3|Per sub-population/.test(r[3]), `residual ${r[0]} carries a proposed rating`);
  const r = (id) => rows.find((x) => x[0] === id);
  assert.ok(r("r1")[1].includes("(IX)") && r("r2")[1].includes("(RD)") && /G5, IX, MG′ and TN/.test(r("r4")[3]), "r1, r2 and r4 name their assumptions");
  for (const name of ["**G5:**", "**IX:**", "**RD** (measured, not proven):", "**MG′:**", "**TN:**"]) assert.ok(text.includes(name), `assumption ${name} is defined`);
  for (const phrase of ["LOW only with the control, MEDIUM without it", "the pre-activation record check is re-run", "(AUTHORIZED, SIGNED, BROADCAST, RECONCILIATION_REQUIRED) without a bound input observation", "every request whose Verify answers CLAIM_PENDING", "with no invalidation, deletion or repair of any record", "kept separate from GAP-9"]) {
    assert.ok(r("r3")[3].includes(phrase), `r3 states its control: "${phrase}"`);
  }
  assert.ok(r("r9")[1].includes("inclusion as spending") && r("r9")[1].includes("any block producer can postpone the withdrawal") && r("r9")[1].includes("No keys or fees are needed"), "r9 is stated precisely");
  assert.ok(r("r7")[1].includes("Two separate statements"), "r7 is split into its two statements (amendment A1-7)");
  const gap2b = tableRows(section, "Item").rows.find((x) => x[0] === "GAP-2b (R3N-B1 approved)");
  for (const phrase of ["r1 and r2 rest on assumptions IX and RD", "r3 on its pre-activation control", "r4 on G5, IX, MG′ and TN", "r9 (any block producer can postpone a withdrawal)", "r13(d″) corner, stated verbatim in §10.3, where B-1 is not described as fixed"]) {
    assert.ok(gap2b[5].includes(phrase), `the GAP-2b row names "${phrase}"`);
  }
  assert.ok(gap2b[2].includes(HOLD_CLAUSE), "the GAP-2b row carries amendment A1-6's hold clause verbatim");
});

test("RC45 C4-07 DOC-05: the app-surface contract lists every RC45 code with its status (the closed-code list and §2.2.6), and each one is a code the runtime gives [RED on 007d739]", () => {
  const section = surfaceSection22();
  const { rows } = tableRows(section, "Code");
  const status = Object.fromEntries(rows.map((r) => [r[0].replace(/`/g, ""), r[1]]));
  const expected = { RECORDED_OUTPUT_SPENT: "409", TREASURY_STATE_UNRESOLVED: "409", FEE_INPUT_NOT_LIVE: "409", SUBMIT_INPUT_UNRESOLVED: "409", WITHDRAWAL_DEPTH_PENDING: "409", CANNOT_REJECT: "409", OBSERVATION_ERROR: "422", TREASURY_STATE_UNDETERMINED: "500", RECONCILE_ANSWER_SHAPE: "500" };
  assert.deepEqual(status, expected, "§2.2.6 lists each code with its status");
  const runtime = read(WR7) + read("server/src/org-roots.js") + read("sdk/src/wallet-requests-v7-kas.js");
  for (const code of Object.keys(expected)) assert.ok(runtime.includes(`"${code}"`), `${code} is a code the runtime gives`);
  const closedList = norm(read(SURFACE)).match(/RC45 adds the codes of §2\.2: [^.]*\./);
  assert.ok(closedList, "the closed-code list names the RC45 codes");
  for (const code of Object.keys(expected)) assert.ok(closedList[0].includes(`\`${code}\``), `the closed-code list names ${code}`);
  const server = read("server/src/org-roots.js");
  assert.match(server, /RECORDED_OUTPUT_SPENT: 409/, "STATUS_BY_CODE maps RECORDED_OUTPUT_SPENT to 409");
  assert.match(server, /TREASURY_STATE_UNRESOLVED: 409/, "STATUS_BY_CODE maps TREASURY_STATE_UNRESOLVED to 409");
});

test("RC45 C4-07 DOC-06: the attribution answer: the UNKNOWN shape names every outcome the runtime serves (and no other), and the ADVANCED shape names every field [RED on 007d739]", () => {
  const text = norm(surfaceSection22());
  assert.ok(text.includes("`{ status: \"UNKNOWN\", rootCovenantId, reason, attribution: { outcome, requestId?, txId?, depthDaa?, requiredDepthDaa: \"1000\" } }`"), "the UNKNOWN shape");
  assert.ok(text.includes("`{ status: \"ADVANCED\", rootCovenantId, txId, requestId, via: \"attribution\", mode: \"FULL\" | \"PARTIAL\", depthDaa, requiredDepthDaa: \"1000\", treasury: { vaultId, state: \"ADVANCED\" | \"UNRESOLVED\" }, settled, unsettled, holds, buildable, reason }`"), "the ADVANCED shape");
  const listed = text.match(/with `outcome` one of ([^.]*)\(the completion refused before its first write\)/);
  assert.ok(listed, "the UNKNOWN outcomes are listed");
  const documented = new Set([...listed[1].matchAll(/`([A-Z_]+)`/g)].map((m) => m[1]));
  const src = read(WR7);
  /* every outcome an attribution refusal can serve; ABSENT is raised only inside the PARTIAL upgrade, whose refusals are not served */
  const served = new Set([...src.matchAll(/attributionRefusal\("([A-Z_]+)"/g)].map((m) => m[1]).filter((o) => o !== "ABSENT"));
  for (const m of src.matchAll(/attributionUnknown\(rootCovenantId, "([A-Z_]+)"/g)) served.add(m[1]);
  for (const m of src.matchAll(/: "(COMPLETION_REFUSED)"/g)) served.add(m[1]);
  assert.deepEqual([...documented].sort(), [...served].sort(), "the documented outcomes are exactly the served ones");
  assert.ok(text.includes("`outOfBandAttribution = { schema: \"policyvault-oob-attribution/1\", via: \"attribution\", txId, requestId, observedVirtualDaa, rootEntryDaa, depthDaa, requiredDepthDaa, mode, modeChangedAt?, treasury: { vaultId, predecessorOutpoint, state }, at }`"), "the marker's shape");
  assert.ok(text.includes("`submissionOutcome: { outcome: \"SUPERSEDED\", proof: { via: \"attribution\", acceptedConflictingTxId, attributedRequestId, spentOutpoint, depthDaa } }`"), "the settlement proof's shape");
  assert.ok(text.includes("SUBMIT_TO_RECORD` naming it: its own transaction is already on the chain, so press Submit on it, then Verify state"), "SUBMIT_TO_RECORD tells the operator to press Submit on the named request, then Verify state");
});

test("RC45 C4-07 DOC-07: the holds and buildability (D4b) are documented with their shapes, the undetermined answer and the only buildability claim [RED on 007d739]", () => {
  const text = norm(surfaceSection22());
  for (const phrase of [
    "`{ scope: \"root\", requestId, state }`",
    "`{ scope: <vaultId>, reason: \"UNRESOLVED\", requestId, txId }`",
    "`buildable = { root, treasuries }`",
    "`holds: null, buildable: null` means not determined",
    "Only `buildable.root === true` means that owner actions on the root and on the listed treasuries, FREEZE included, can be built again as of this check",
    "This computation never releases a hold."
  ]) assert.ok(text.includes(phrase), `§2.2.2 states: ${phrase}`);
});

test("RC45 C4-07 DOC-08: the build-time liveness guard is documented with exactly what it prevents and what it does not prevent [RED on 007d739]", () => {
  const text = norm(surfaceSection22());
  for (const phrase of [
    "**What it prevents, exactly:** recording a root request, and reserving the root with it, when the request spends a root or v0.7-kas treasury output that the synced node does not report unspent at build time",
    "**What it does not prevent:** a spend accepted after this read, or one only in the mempool",
    "a broadcast of the request's own transaction outside PolicyVault; a node that misreports. It does not promise that an output stays unspent after the build.",
    "**It never closes a usable treasury:** it keeps no state",
    "**Behaviour change:** a root build with an explicit fee input now also needs the node."
  ]) assert.ok(text.includes(phrase), `§2.2.4 states: ${phrase}`);
});

test("RC45 C4-07 DOC-09: R3N-B1 is documented: the submit read with every finding and its extra shape (E1s included), the own-transaction distinction, the two-step withdrawal with exactly the runtime's CANNOT_REJECT findings, K1' and K2, and the constants as the runtime defines them [RED on 007d739]", () => {
  const section = surfaceSection22();
  const text = norm(section);
  for (const phrase of [
    "`extra.submitRead = { finding, role, outpoint, withdrawal: \"TWO_STEP\" | \"NONE\", existence: \"E1\" | \"E1s\" | \"E2\" | \"E3\" | null, existenceGap: \"NO_MARKER\" | \"ANCHOR_UNAVAILABLE\" | \"CREATOR_NOT_LOCATED\" | null }`",
    "`409 SUBMIT_INPUT_UNRESOLVED`, finding `ROOT_INPUT_NOT_LIVE`",
    "`409 SUBMIT_INPUT_UNRESOLVED`, finding `INPUT_CONTRADICTED`",
    "`409 RECORDED_OUTPUT_SPENT`, finding `CONFLICTING_SPEND`",
    "`409 SUBMIT_INPUT_UNRESOLVED`, finding `INPUT_EXISTENCE_UNPROVEN`",
    "an output of the request's own transaction observed | the existing submit route",
    "\"Never attempted by the server\" does not mean that the request's transaction was never broadcast",
    "`E1s`: another output of the same creating transaction is observed unspent",
    "`extra.feeInput = { index, outpoint, reason: \"ABSENT\" | \"MISMATCH\" | \"READ_FAILED\", detail }`",
    "the largest ordinary UTXO at least 1,000 DAA deep when one exists",
    "it never refuses for freshness",
    "The slot-request, slot-signature and finalize saves (and a succession's signature save) evaluate E2 and E3",
    "**Step 1** records only the anchor",
    "`extra.earliestDaa` = DAA(A1) + 1,000 and `extra.latestDaa` = DAA(A1) + 12,000",
    "(inclusion in a block counts, accepted or not)",
    "No claim, receipt, root or treasury state, no SUPERSEDED and no `submissionOutcome` is written",
    "**Uncertainty never withdraws:** no withdrawal, claim release or retry under a new key rests on an unproven, contradictory, not-yet-final or unreadable observation",
    "**The request's own transaction wins during the wait:**"
  ]) assert.ok(text.includes(phrase), `§2.2.5 states: ${phrase}`);
  const listed = text.match(/`409 CANNOT_REJECT` with `extra\.withdrawal\.finding` one of ([^,]*(?:, [^,]*)*?) or `([A-Z_]+)`, with nothing written/);
  assert.ok(listed, "the CANNOT_REJECT findings are listed");
  const documented = new Set([...(listed[1] + " `" + listed[2] + "`").matchAll(/`([A-Z_]+)`/g)].map((m) => m[1]));
  const runtime = new Set([...read(WR7).matchAll(/cannot\("([A-Z_]+)"/g)].map((m) => m[1]));
  assert.deepEqual([...documented].sort(), [...runtime].sort(), "the documented findings are exactly the runtime's");
  const src = read(WR7);
  const { rows } = tableRows(section, "Constant");
  const value = Object.fromEntries(rows.map((r) => [r[0].replace(/`/g, ""), r[1]]));
  assert.ok(/const INPUT_SPENT_WITHDRAWAL_DEPTH_DAA = ATTRIBUTION_DEPTH_DAA;/.test(src) && /const ATTRIBUTION_DEPTH_DAA = 1000n;/.test(src), "the runtime's depth constant");
  assert.equal(value.INPUT_SPENT_WITHDRAWAL_DEPTH_DAA, "1000");
  assert.equal(value.CHAIN_ANCHOR_HOPS, src.match(/const CHAIN_ANCHOR_HOPS = (\d+);/)[1]);
  assert.equal(value.WITHDRAWAL_ANCHOR_MAX_AGE_DAA, src.match(/const WITHDRAWAL_ANCHOR_MAX_AGE_DAA = (\d+)n;/)[1]);
  assert.equal(value.WITHDRAWAL_SCAN_MAX_BATCHES, src.match(/const WITHDRAWAL_SCAN_MAX_BATCHES = (\d+);/)[1]);
});

test("RC45 C4-07 DOC-10: the documented withdrawal texts, hold clause and UNRESOLVED explanation are the served ones, with the owner's sentence verbatim [RED on 007d739]", () => {
  const text = norm(surfaceSection22());
  for (const [name, s] of [["the owner's sentence", OWNER_SENTENCE], ["text S", TEXT_S], ["T-B1", T_B1], ["amendment A1-6's hold clause", HOLD_CLAUSE], ["writer decision item 1", UNRESOLVED_EXPLANATION]]) {
    assert.ok(text.includes(s), `§2.2 quotes ${name} verbatim`);
  }
  const served = read("web/app-v4.js") + read("web/org-root-ui.js") + read("web/refusal-explain.js");
  for (const s of [OWNER_SENTENCE, TEXT_S, HOLD_CLAUSE, UNRESOLVED_EXPLANATION]) assert.ok(served.includes(s), `the web serves: ${s.slice(0, 60)}…`);
  assert.ok(read(WR7).includes(`const WITHDRAWAL_NON_REVOCATION_SENTENCE = "${OWNER_SENTENCE}";`), "the SDK's pending message ends with the owner's sentence");
  const reject = norm(read(SURFACE)).match(/\| `POST \/org-roots\/:rootId\/requests\/:id\/reject` \|[^|]*\|([^|]*)\|/);
  assert.ok(reject && reject[1].includes(OWNER_SENTENCE), "the reject route row carries the owner's sentence");
});

test("RC45 C4-07 DOC-11: statements the repair made false are corrected (the reject row's terminal REFUSED, the finalized-request sentences of both documents, the rollback section's first sentence) [RED on 007d739]", () => {
  const surface = norm(read(SURFACE)), lead = norm(read(LEAD5));
  assert.equal(surface.includes("terminal REFUSED (hosted-layer withdrawal only; never a chain fact)"), false, "the reject row no longer calls a withdrawal terminal");
  assert.ok(surface.includes("one exception for REFUSED: a withdrawn v0.7-kas delegate rule change whose transaction is accepted after a broadcast outside PolicyVault is attributed by Verify and becomes CHAIN_VERIFIED"), "the request record's state ladder states the exception");
  assert.equal(surface.includes("A finalized request cannot be withdrawn and is not re-checked at submit"), false, "the app-surface contract's finalized-request sentence is corrected");
  assert.ok(surface.includes("A finalized request is not re-checked for its period start at submit and cannot be withdrawn on that ground"), "the corrected sentence");
  assert.equal(lead.includes("are not refused at submit, because neither can be withdrawn"), false, "lead5's finalized-request sentence is corrected");
  assert.ok(lead.includes("are not re-checked for their period start at submit, because neither can be withdrawn on that ground"), "lead5's corrected sentence");
  assert.ok(lead.includes("Apart from the organization-root records of §10 (item 8), RC45 writes only shapes that RC44 and RC42 can read"), "the rollback section's first sentence is scoped");
  assert.ok(lead.includes("8. The organization-root records of §10 are not recognized by RC44 or RC42"), "the rollback section lists the organization-root records");
});

test("RC45 C4-07 DOC-12: the carried disclosures are stated (K1' node wait, another root's identifiers, the summary routes failing closed, the upgrade's history line, a reversed upgrade, replayed completions, the internal 500 codes, read stateUnresolved first) [RED on 007d739]", () => {
  const lead = norm(lead5Section10()), surface = norm(surfaceSection22());
  for (const phrase of [
    "**Saves that wait for the node (LOW).** The slot-request, slot-signature, finalize and succession-signature saves of a root request now connect to the node to record existence evidence, with no overall timeout.",
    "**Another root's identifiers in a refusal (LOW).**",
    "with that other root's attributed request id and txid in the message",
    "**Summary routes fail closed on one damaged record.**",
    "A crash between the treasury record write and the history line of a later Verify's upgrade leaves the upgrade without its line for good",
    "**A reversed upgrade.**",
    "its CHAIN_VERIFIED history line carries `via` `reconcile` or `submit-recovery`",
    "`TREASURY_STATE_UNDETERMINED` and `RECONCILE_ANSWER_SHAPE` cannot be reached through the routes with the current SDK, have no closed web explanation and are shown verbatim."
  ]) assert.ok(lead.includes(phrase), `lead5 §10.4 discloses: ${phrase}`);
  assert.ok(surface.includes("Read it first: when it is set, `status`, `generation`, `latestTransitionTxId`, `agents`, `approvers`, `approvalM` and `live` are the last record"), "API consumers are told to read stateUnresolved first");
  assert.ok(surface.includes("one entry per treasury with exactly ten string fields `vaultId`, `requestId`, `txId`, `from` (`\"PARTIAL\"`), `mode` (`\"FULL\"`), `treasury` (`\"ADVANCED\"`), `outpoint` (`\"<txId>:<index>\"`), `depthDaa`, `requiredDepthDaa` (`\"1000\"`) and `reason`"), "the treasuryUpgrades shape");
});

test("RC45 C4-07 DOC-13 (holds): the six passages the public copy quotes from the remediation record stay verbatim [PIN: holds on 007d739]", () => {
  const text = read(LEAD5);
  const joined = text.replace(/[ \t]*\n[ \t]*/g, " ");
  for (const q of ["(floor((T − 1 − S) / L) + 1) × B − σ", "so a dishonest server can still commit a stale start", "paused vault allows no delegate spend", "UNKNOWN leaves no durable marker."]) assert.ok(text.includes(q), `exact quote kept: ${q}`);
  for (const q of ["At consensus the owner can still pause or recover the current output with one owner signature plus a fee input.", "Keep one output of the recover unspent until Verify shows RECOVERED"]) assert.ok(joined.includes(q), `wrapped quote kept: ${q}`);
});

test("RC45 C4-07 DOC-14: the new sections never use the word for an external engagement, never say the changed treasury was recovered or that the recovery is complete (beyond the label's negation), and never describe B-1 or L2-01 as fixed [RED on 007d739]", () => {
  for (const [name, section] of [["lead5 §10", lead5Section10()], ["app-surface §2.2", surfaceSection22()]]) {
    const text = norm(section);
    assert.equal(/audit/i.test(text), false, `${name}: no word for an external engagement`);
    assert.equal(/\brecovered\b/i.test(text), false, `${name}: nothing is called recovered`);
    /* "submit-recovery" is a runtime `via` value (a replayed completion), not a claim */
    const recovery = [...text.matchAll(/(?<!submit-)\brecovery\b/gi)].map((m) => text.slice(Math.max(0, m.index - 40), m.index + 8));
    for (const r of recovery) assert.ok(r.endsWith("Not a complete root-and-treasury recovery"), `${name}: "recovery" appears only in the label's negation; found: ${r}`);
    assert.equal(/\b(?:B-1|L2-01|GAP-2b?)\s+(?:is\s+|was\s+)?(?:now\s+)?(?:fixed|repaired|resolved|closed)\b/i.test(text), false, `${name}: B-1, L2-01 and GAP-2/2b are never described as fixed`);
    assert.equal(/\bcomplete (?:root-and-treasury )?recovery\b/i.test(text.replace("Not a complete root-and-treasury recovery", "")), false, `${name}: no complete-recovery claim`);
  }
});

/* ---- C4-07a: the corrections after the C4-07 independent item check ---- */

const API_SPEC = "docs/postlaunch/platform-agent-api-spec.md";
/* every Markdown document under docs/ (recursively) */
function docsMarkdown() {
  const out = [];
  const walk = (rel) => {
    for (const e of fs.readdirSync(path.join(ROOT, rel), { withFileTypes: true })) {
      const r = `${rel}/${e.name}`;
      if (e.isDirectory()) walk(r);
      else if (e.name.endsWith(".md")) out.push(r);
    }
  };
  walk("docs");
  return out;
}
/* the body of one top-level function of a source file, from its declaration to the next top-level declaration */
function functionBody(src, name) {
  const a = src.indexOf(`\nasync function ${name}(`) >= 0 ? src.indexOf(`\nasync function ${name}(`) : src.indexOf(`\nfunction ${name}(`);
  assert.ok(a >= 0, `the runtime defines ${name}`);
  const b = src.slice(a + 1).search(/\n(?:async function|function|const|\/\*) /);
  return b < 0 ? src.slice(a + 1) : src.slice(a + 1, a + 1 + b + 1);
}

test("RC45 C4-07a DOC-15 (F01): lead5 §10.3 states r13(d″)'s hold sentence as writer clarification 03's binding replacement, verbatim, as its own line of the r13(d″) block; amendment A1's replaced sentence (after the exit 'C4-03 settlement settles the request', false at runtime) appears in no document; the GAP-2 row says the same about the owners' exit [RED on 938f78f]", () => {
  const section = lead5Section10();
  const lines = section.split("\n");
  const at = lines.indexOf("**The remaining corner, stated precisely (r13(d″))**");
  const rating = lines.findIndex((l, i) => i > at && l.startsWith("**Proposed rating:**"));
  assert.ok(at >= 0 && rating > at, "the r13(d″) block is present");
  assert.deepEqual(lines.slice(at, rating).filter((l) => l === R13D2_HOLD).length, 1, "the r13(d″) block states clarification 03's hold sentence once, verbatim, as its own line");
  assert.equal(norm(read(LEAD5)).split(R13D2_HOLD).length - 1, 1, "the binding hold sentence appears exactly once in the record");
  for (const rel of docsMarkdown()) {
    const text = norm(read(rel));
    assert.equal(text.includes(norm(R13D2_HOLD_FALSE)), false, `${rel}: amendment A1's replaced hold sentence is gone`);
    assert.equal(/settlement settles the request/.test(text), false, `${rel}: no document says that settlement settles the request after the owners' exit`);
    assert.equal(/the hold ends only through/i.test(text.replace(/\*\*/g, "")), false, `${rel}: no document says that the hold ends through the on-chain exit`);
  }
  const gap2 = tableRows(section, "Item").rows.find((r) => r[0] === "GAP-2");
  assert.ok(gap2[2].includes("only the owners' direct on-chain exit acts on it, which moves the root outside PolicyVault (GAP-1): Verify then answers UNKNOWN and writes nothing, and no settlement runs."), `the GAP-2 row agrees with the binding sentence; it says: ${gap2[2]}`);
  /* the runtime the sentence describes: the settlement hook runs only while the recorded root outpoint is observed
   * unspent (reconcile-v7's live branch), so after the owners' exit no settlement runs; the dynamic proof is B1-05c */
  const reconcile = read("sdk/src/reconcile-v7.js");
  const live = reconcile.indexOf("  if (liveRef) {");
  const hook = reconcile.indexOf("attributionSettlementHook(config, rpc, root)");
  assert.ok(live >= 0 && hook > live && reconcile.slice(live, hook).split("\n  }").length === 1, "the settlement hook is called only inside reconcileRoot's live-outpoint branch");
  assert.ok(/attributionUnknown\(rootCovenantId, "NO_CANDIDATE"|attributionRefusal\("NO_CANDIDATE"/.test(read(WR7)), "an unrecorded root move answers UNKNOWN NO_CANDIDATE");
});

test("RC45 C4-07a DOC-16 (F02): the agent API spec no longer says a finalized root request is 'not refused at submit (neither can be withdrawn)'; it states the period-start rule and the submit read's 409 RECORDED_OUTPUT_SPENT with nothing written and the two-step input-spent withdrawal, as the app-surface contract's §2.2.5 does; its quoted window formula is unchanged [RED on 938f78f]", () => {
  const raw = read(API_SPEC);
  const spec = norm(raw);
  assert.equal(spec.includes("not refused at submit (neither can be withdrawn)"), false, "the false statement is gone");
  assert.equal(/not refused at submit/.test(spec), false, "no sentence says a finalized root request is not refused at submit");
  for (const phrase of [
    "a signed `policyvault-0.7-kas` creation and a finalized root request are not re-checked for their period start at submit, and neither can be withdrawn on that ground.",
    "a finalized root request's Submit first reads every input the request spends (`v0.7-app-surface-contract.md` §2.2.5)",
    "when a non-root input is proven spent by another transaction it refuses `409 RECORDED_OUTPUT_SPENT` with nothing written and nothing broadcast",
    "the request can then be withdrawn (`POST /org-roots/:rootId/requests/:id/reject`) in two steps, at least 1,000 DAA apart, once that spend and the input's existence are final",
    "another unresolved input read refuses `409 SUBMIT_INPUT_UNRESOLVED`, and an unreadable chain position `422 OBSERVATION_ERROR`, also with nothing written"
  ]) assert.ok(spec.includes(phrase), `the agent API spec states: ${phrase}`);
  /* consistency with the app-surface contract (§2.2.5) and the runtime */
  const surface = norm(surfaceSection22());
  for (const phrase of [
    "and writes nothing on any refusal",
    "`409 RECORDED_OUTPUT_SPENT`, finding `CONFLICTING_SPEND`: spent by another transaction; withdrawable in two steps",
    "`409 SUBMIT_INPUT_UNRESOLVED`, finding `INPUT_EXISTENCE_UNPROVEN`",
    "**Step 1** records only the anchor",
    "`extra.earliestDaa` = DAA(A1) + 1,000"
  ]) assert.ok(surface.includes(phrase), `§2.2.5 states: ${phrase}`);
  const submitRead = functionBody(read(WR7), "submitReadAnswer");
  assert.ok(submitRead.includes("withdrawal: code === \"RECORDED_OUTPUT_SPENT\" ? \"TWO_STEP\" : \"NONE\""), "the runtime offers the two-step withdrawal exactly for RECORDED_OUTPUT_SPENT");
  /* (holds) the passage the public copy quotes from this file stays verbatim */
  assert.ok(raw.includes("`W(L) = max(L − 6,000, 600)` DAA"), "the quoted window formula is unchanged");
});

test("RC45 C4-07a DOC-17 (F03): the app-surface contract states the wire convention for a refusal's additional fields (top-level members of the HTTP error envelope, error.submitRead and so on; extra.* only in the SDK's PolicyVaultApiError and in-process errors), it covers every extra field §2.2 names, and it matches server.js and http-client.js [RED on 938f78f]", () => {
  const section = surfaceSection22();
  const text = norm(section);
  for (const phrase of [
    "**Refusal fields on the wire.**",
    "The HTTP answer has no `extra` member: these fields are top-level members of the error envelope, beside `code` and `message`",
    "`{ \"error\": { \"code\": \"RECORDED_OUTPUT_SPENT\", \"message\": \"…\", \"submitRead\": { … } } }`",
    "A raw HTTP client reads `error.submitRead`, `error.feeInput`, `error.earliestDaa`, `error.latestDaa` and `error.withdrawal.finding`.",
    "The SDK's HTTP client error `PolicyVaultApiError` (`sdk/src/http-client.js`) exposes the same members as `err.extra.submitRead` and so on"
  ]) assert.ok(text.includes(phrase), `§2.2 states: ${phrase}`);
  const convention = text.slice(text.indexOf("**Refusal fields on the wire.**"), text.indexOf("**Why.**"));
  assert.ok(convention.length > 0 && text.indexOf("**Refusal fields on the wire.**") < text.indexOf("#### 2.2.1"), "the convention is stated at the head of §2.2, before its first rule");
  const named = new Set([...text.matchAll(/`extra\.([A-Za-z]+)/g)].map((m) => m[1]));
  for (const field of named) {
    assert.ok(convention.includes(`\`extra.${field}\``), `the convention lists extra.${field}`);
    assert.ok(convention.includes(`\`error.${field}`), `the convention gives the wire name error.${field}`);
  }
  assert.deepEqual([...named].sort(), ["earliestDaa", "feeInput", "latestDaa", "submitRead", "withdrawal"], "§2.2 names exactly these refusal fields");
  const reject = norm(read(SURFACE)).match(/\| `POST \/org-roots\/:rootId\/requests\/:id\/reject` \|[^|]*\|([^|]*)\|/);
  assert.ok(reject && reject[1].includes("`error.withdrawal.finding` of the HTTP error envelope, `extra.withdrawal.finding` in the SDK"), "the reject route row gives the wire name");
  /* runtime agreement: the server spreads `extra` into the envelope; the SDK client lifts the envelope's other members into `extra` */
  assert.ok(read("server/src/server.js").includes("{ error: { code: error.code || \"INTERNAL\", message: error.message, ...(error.extra ? { ...error.extra } : {}) } }"), "server.js sends `extra`'s members at the top level of the error envelope");
  assert.ok(read("sdk/src/http-client.js").includes("this.extra = envelope ? Object.fromEntries(Object.entries(envelope).filter(([k]) => k !== \"code\" && k !== \"message\")) : {};"), "PolicyVaultApiError exposes the envelope's other members as `extra`");
  const wr7 = read(WR7);
  for (const key of ["{ submitRead: {", "{ feeInput: {", "{ earliestDaa: ", "latestDaa: ", "{ withdrawal: { finding } }"]) assert.ok(wr7.includes(key), `the runtime's refusal carries ${key}`);
});

test("RC45 C4-07a DOC-18 (F05 a-e): the five wording corrections hold and agree with the runtime: (a) the pointer save never refuses; (b) text S is stated for every owner-signed withdrawal except the input-spent one, which states T-B1 instead; (c) only the treasury output is read twice in the later-Verify upgrade; (d) the build's OBSERVATION_ERROR also covers an anchor that left the selected chain by its recheck; (e) §10.1 states the existence-evidence condition of RECORDED_OUTPUT_SPENT [RED on 938f78f]", () => {
  const surface = norm(surfaceSection22()), lead = norm(lead5Section10());
  const wr7 = read(WR7);
  /* (a) */
  assert.equal(surface.includes("each after a reload that refuses with `STORE_CHANGED` if the request or the root changed"), false, "(a) the imprecise writes sentence is gone");
  assert.ok(surface.includes("Each save of the request follows a reload that refuses with `STORE_CHANGED`, writing nothing, if the request changed or the root record no longer names the request's root predecessor as live. The pointer save reloads the root and clears its pointer only when it still names this request; it never refuses."), "(a) the writes are stated precisely");
  const release = functionBody(wr7, "releaseRootReservation");
  assert.ok(release.includes("root.pendingRequestId === request.id") && !/throw|STORE_CHANGED|cannot\(/.test(release), "(a) the runtime's pointer save clears only its own pointer and never refuses");
  /* (b) */
  assert.ok(surface.includes("Every withdrawal of a request that carries owner signatures, except the input-spent withdrawal, states: \"Withdrawing marks this request withdrawn"), "(b) text S excepts the input-spent withdrawal");
  assert.ok(surface.includes("The input-spent withdrawal states, in place of that text (and the `WITHDRAWAL_DEPTH_PENDING` message ends with its first sentence): \"Withdrawal does not revoke signatures"), "(b) the input-spent withdrawal states T-B1 in place of S");
  const app = read("web/app-v4.js");
  const spentLines = app.split("\n").filter((l) => /const (?:INPUT_SPENT_WITHDRAWAL_TEXT|WITHDRAW_SPENT_STEP1_CONFIRM|WITHDRAW_SPENT_STEP2_CONFIRM) =/.test(l));
  assert.equal(spentLines.length, 3, "(b) the web defines the input-spent withdrawal texts");
  for (const l of spentLines) assert.equal(/WITHDRAWAL_TEXT_S|Withdrawing broadcasts nothing/.test(l), false, "(b) the web's input-spent withdrawal texts do not state S");
  /* (c) */
  assert.equal(surface.includes("both unchanged across two reads"), false, "(c) the imprecise two-reads clause is gone");
  assert.ok(surface.includes("only when it freshly observes, in this order: that output exact and unspent; every frozen input of the attributed request reported spent (one read of each input address); when the root stands at the attributed successor, the root successor exact at the same accepting DAA; and that output read a second time, unchanged; at depth ≥ 1,000 DAA. Only the treasury output is read twice."), "(c) the upgrade's reads are stated precisely");
  const upgrade = functionBody(wr7, "observeTreasuryUpgrade");
  assert.equal(upgrade.split("await read(treasuryAddress, \"the treasury successor address\")").length - 1, 2, "(c) the runtime reads the treasury output twice");
  assert.equal(upgrade.split("await read(address, \"an input address of the attributed transaction\")").length - 1, 1, "(c) the runtime reads each input address once");
  /* (d) */
  assert.ok(surface.includes("a null anchor (it could not be read, or it left the selected chain by the recheck) while a non-root input is less than 1,000 DAA deep `422 OBSERVATION_ERROR`"), "(d) §2.2.5 states both causes");
  const codes = Object.fromEntries(tableRows(surfaceSection22(), "Code").rows.map((r) => [r[0].replace(/`/g, ""), r[3]]));
  assert.ok(codes.OBSERVATION_ERROR.includes("or at build the anchor left the selected chain by its recheck"), "(d) the §2.2.6 row states both causes");
  assert.ok(lead.includes("when the chain anchor cannot be read, or left the selected chain by its recheck, while an input is less than 1,000 DAA deep"), "(d) lead5 §10.4 states both causes");
  assert.ok(lead.includes("A build anchor that cannot be read, or that left the selected chain by its recheck, now refuses the build while any non-root input is less than 1,000 DAA deep."), "(d) lead5 r13(b) states both causes");
  assert.ok(functionBody(wr7, "observeInputsAtBuild").includes("if (again.daaScore !== anchor.daaScore) anchor = null;") && wr7.includes("could not be read (or its anchor left the selected chain) while an input of this request is less than 1,000 DAA deep"), "(d) the runtime refuses for both causes");
  /* (e) */
  assert.ok(lead.includes("A non-root input reported absent answers `409 RECORDED_OUTPUT_SPENT` (spent by another transaction) only when the root input is still reported unspent, no output of the request's own transaction is observed, and existence evidence shows that the input was created on the selected chain for good; without that evidence it is not treated as spent (`409 SUBMIT_INPUT_UNRESOLVED`)."), "(e) §10.1 states the existence-evidence condition");
  assert.equal(lead.includes("An input spent by another transaction answers `409 RECORDED_OUTPUT_SPENT`"), false, "(e) the condition-free sentence is gone");
});
