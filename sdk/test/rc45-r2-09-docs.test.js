"use strict";
/*
 * RC45 R2-09 — DOCUMENTATION AND SPECIFICATION TEXT FOR THE HOSTED DELEGATE
 * PERIOD-START REPAIR. Internal RED-first regression material for the RC45
 * candidate; not an audit.
 *
 * THE DEFECT (b89f0f7): the reconciliation-remediation record still says the
 * hosted period-start finding is not fixed ("RC45 does not fix it"); the
 * governance specification still says a governed execution's after-state is
 * derived from the signed proposal content with every periodStartDaa change an
 * expansion, which the hosted pipeline's anchoring departs from; and the
 * v0.7 app-surface contract does not state that a delegate rule change must
 * collect its owner approvals and be finalized within the delegate's window.
 *
 * REQUIRED TEXT (pinned here):
 *   - docs/postlaunch/lead5-reconciliation-remediation.md: the related-finding
 *     block after the banking section states that the repair does not change
 *     the banking ("This does **not** change the banking above"), no longer
 *     says "RC45 does not fix it", and the banking section itself (from its
 *     "## 6." heading to the related-finding block) is byte-identical to
 *     b89f0f7;
 *   - docs/postlaunch/governance-spec.md: §6.2 execution step 4 carries the
 *     narrow, stated exception after "re-runs `classifyPolicyDelta`"; the M8
 *     catalogue row and the §5.1 periodStartDaa row carry their notes, their
 *     classification unchanged;
 *   - docs/postlaunch/v0.7-app-surface-contract.md: the "Delegate rule changes
 *     and approval time" paragraph;
 *   - (holds) no sentence of these specifications or of the agent API, MCP and
 *     Python client specifications says the banking is removed, fixed or
 *     closed, or that the hosted repair removes it (the banking is a property
 *     of the installed covenants that this repair does not change).
 * The release-notes text is outside the candidate and is pinned by its own
 * tooling's tests.
 *
 * Layer: UNIT (static reads of checked-in documents). No store, no node.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = path.join(__dirname, "..", "..");
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const norm = (s) => String(s).replace(/\s+/g, " ").trim();
const LEAD5 = "docs/postlaunch/lead5-reconciliation-remediation.md";
const GOV = "docs/postlaunch/governance-spec.md";
const SURFACE = "docs/postlaunch/v0.7-app-surface-contract.md";

/* The banking section of the remediation record, from its "## 6." heading up to (not including) the related-finding
 * block that follows it, as lines joined by "\n" plus a final "\n"; at b89f0f7 this is lines 485-543. */
const BANKING_SECTION_SHA256 = "a695c92a1e4c678216287498d72a37e0e5cd665cd6d69e0d5d96f256461a68f6";
function bankingSection(text) {
  const lines = text.split("\n");
  const a = lines.findIndex((l) => l.startsWith("## 6. Delegate budget banking"));
  const b = lines.findIndex((l, i) => i > a && l.startsWith("**Related finding: HOSTED-PERIOD-START-ANCHOR-01"));
  assert.ok(a >= 0, "the banking section heading is present");
  assert.equal(lines.filter((l) => l.startsWith("## 6. Delegate budget banking")).length, 1, "exactly one banking section");
  assert.ok(b > a, "the related-finding block follows the banking section");
  const next = lines.findIndex((l, i) => i > b && l.startsWith("## "));
  return { section: lines.slice(a, b).join("\n") + "\n", related: lines.slice(b, next < 0 ? lines.length : next).join("\n") };
}

test("RC45 R2-09 docs (holds): the banking section of the remediation record (its heading up to the related-finding block) is byte-identical to b89f0f7", () => {
  const { section } = bankingSection(read(LEAD5));
  assert.equal(crypto.createHash("sha256").update(section, "utf8").digest("hex"), BANKING_SECTION_SHA256, "the banking text is unchanged by the repair's records");
});

test("RC45 R2-09 docs: the remediation record's related-finding block states that the hosted repair does not change the banking (\"This does **not** change the banking above\") and no longer says \"RC45 does not fix it\" [RED on b89f0f7]", () => {
  const text = read(LEAD5);
  const { related } = bankingSection(text);
  assert.ok(norm(related).includes("This does **not** change the banking above"), `the related-finding block states that the repair does not change the banking; it says: ${norm(related).slice(0, 600)}`);
  assert.equal(text.includes("RC45 does not fix it"), false, "the record no longer says the finding is not fixed");
});

test("RC45 R2-09 docs: governance-spec §6.2 execution step 4 carries the narrow hosted exception for v0.4-family agent leaves, after \"re-runs `classifyPolicyDelta`\" [RED on b89f0f7]", () => {
  const text = read(GOV);
  const a = text.indexOf("4. **Execution**"), b = text.indexOf("5. **Reconciliation**");
  assert.ok(a >= 0 && b > a, "§6.2 steps 4 and 5 are present");
  const step4 = norm(text.slice(a, b));
  const exception = norm("Narrow exception for v0.4-family agent leaves: for a leaf the approved change adds, replaces or re-policies, the hosted pipeline commits `periodStartDaa = max(approved, DAA score at the build)` — the start may be later than approved, never earlier — and commits `periodSpent` exactly as approved. Moving a start later with the spent amount unchanged never raises the amount the delegate can spend at any time; classification stays on the approved change.");
  const at = step4.indexOf(exception);
  assert.ok(at >= 0, `step 4 states the exception; it says: ${step4}`);
  const rerun = step4.indexOf("re-runs `classifyPolicyDelta`");
  assert.ok(rerun >= 0 && rerun < at, "the exception follows \"re-runs `classifyPolicyDelta`\"");
  assert.ok(step4.includes("DERIVED FROM THE SIGNED PROPOSAL CONTENT"), "the step's rule itself is kept; the exception is stated beside it");
});

test("RC45 R2-09 docs: the governance-spec M8 catalogue row carries the hosted-exception note in its classification cell, the classification itself unchanged [RED on b89f0f7]", () => {
  const lines = read(GOV).split("\n");
  const m8 = lines.filter((l) => l.startsWith("| M8 |"));
  assert.equal(m8.length, 1, "one M8 row");
  assert.ok(m8[0].includes("any `periodStartDaa` change EXPANSION"), "the M8 classification is unchanged");
  assert.ok(m8[0].includes("(hosted exception: a later start with unchanged `periodSpent`, set by the pipeline for a new or changed leaf, is not an expansion — §6.2 step 4)"), `the M8 row carries the hosted-exception note; it says: ${m8[0]}`);
});

test("RC45 R2-09 docs: the governance-spec §5.1 periodStartDaa row carries the note that the hosted pipeline's own later start is not a requested change and is not classified, the classification itself unchanged [RED on b89f0f7]", () => {
  const lines = read(GOV).split("\n");
  const start = lines.filter((l) => l.startsWith("| leaf `periodStartDaa` |"));
  assert.equal(start.length, 1, "one §5.1 periodStartDaa row");
  assert.ok(start[0].includes("any change") && start[0].includes("`AGENT_PERIOD_PHASE_CHANGED`"), "the §5.1 classification is unchanged");
  assert.ok(start[0].includes("The hosted pipeline's own later start for a new or changed leaf (§6.2 step 4) is not a requested change and is not classified."), `the §5.1 row carries the note; it says: ${start[0]}`);
});

test("RC45 R2-09 docs: the v0.7 app-surface contract carries the \"Delegate rule changes and approval time\" paragraph (every owner approval and the finalize within the delegate's window of the build; a slower quorum can only withdraw and rebuild; where the web shows the deadline; the API later-start option) [RED on b89f0f7]", () => {
  const text = norm(read(SURFACE));
  assert.ok(text.includes("Delegate rule changes and approval time"), "the paragraph is titled");
  const paragraph = norm("A delegate rule change must collect every owner approval and be finalized within the new or changed delegate's budget period minus ten minutes (never less than one minute) of its build — 50 minutes for a 1-hour period, 23 h 50 min for a daily one. A slower quorum cannot finalize it: the request can then only be withdrawn and built again. The web shows the deadline on the request, next to each approval button and on the Change delegate rules form (on the request it shows the deadline as unknown when the treasury's installed delegate rules cannot be loaded; PolicyVault then decides at finalize). API, SDK and MCP callers may request a later budget period start, which extends the window; the web has no such input in this release.");
  assert.ok(text.includes(paragraph), "the contract states the approval-time limit exactly");
  assert.ok(text.indexOf("Delegate rule changes and approval time") < text.indexOf(paragraph), "under its title");
});

/* A sentence that mentions the banking together with a removal / fix verb and no negation or continuity word. */
const REMOVAL = /\b(remov(?:e|es|ed|ing|al)|eliminat\w*|fix(?:es|ed)?|clos(?:e|es|ed)|prevent(?:s|ed)?|resolv\w*|no longer|stops?|stopped|ends?|ended)\b/i;
const KEEPS = /\b(not|never|unchanged|still|remains?|cannot|without|keeps?|stays?)\b|n't\b/i;
function bankingRemovalClaims(text) {
  const sentences = norm(text).split(/(?<=[.!?;:])\s+|\s+-\s+|\s+\|\s+/);
  return sentences.filter((s) => /\bbank(?:s|ed|ing)?\b/i.test(s) && REMOVAL.test(s) && !KEEPS.test(s));
}

test("RC45 R2-09 docs (holds): no sentence of the remediation record, the governance, agent API, MCP, Python client or v0.7 app-surface specifications says the banking is removed, fixed or closed (a mention with a removal verb always carries a negation or a continuity word)", () => {
  /* the detector itself: */
  assert.equal(bankingRemovalClaims("RC45 removes the banking.").length, 1, "control: a removal claim is found");
  assert.equal(bankingRemovalClaims("The hosted repair fixes delegate budget banking for hosted paths.").length, 1, "control: a fix claim is found");
  assert.equal(bankingRemovalClaims("This does **not** change the banking above: an idle leaf still banks one budget per elapsed period.").length, 0, "control: the required statement is not a claim");
  for (const rel of [LEAD5, GOV, SURFACE, "docs/postlaunch/platform-agent-api-spec.md", "docs/postlaunch/mcp-interface-spec.md", "docs/postlaunch/python-client-spec.md"]) {
    assert.deepEqual(bankingRemovalClaims(read(rel)), [], `${rel}: no sentence claims the banking is removed`);
  }
});
