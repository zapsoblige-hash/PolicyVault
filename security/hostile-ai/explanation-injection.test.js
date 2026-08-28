"use strict";

/*
 * HOSTILE-AI SURFACE 26 — PROBE GROUP E: EXPLANATION / RENDERING SURFACES
 * (layer: UNIT / ADVERSARIAL; docs/postlaunch/hostile-ai-review.md §E).
 *
 * The completion standard requires "human-readable intent/governance
 * explanations in UI + structured API/agent equivalents", and the mobile
 * architecture decision states the load-bearing rule explicitly: there is
 * exactly ONE implementation of the text a human reads before authorizing
 * money to move, and every renderer displays `outcome.lines` VERBATIM AND
 * IN ORDER, composing no sentence of its own.
 *
 * That makes the LINE ARRAY a trust boundary in its own right. This file
 * attacks it: can content that an upstream builder puts into a manifest
 * (or that a verifier puts into a failure detail) FABRICATE LINES inside
 * the pre-signing ceremony — turning a DO-NOT-SIGN into something that
 * reads like a PASS, or adding a second, false payment/fee line to a
 * genuinely verified transaction?
 *
 * RESULT SUMMARY (see the review doc for severity/classification):
 *   FINDING H-1  — YES for note details. `manifest.warnings[].detail` and
 *                  `manifest.unexpectedEffects[].detail` accept ANY string
 *                  up to 2000 chars (core/intent/manifest.js
 *                  requireDetail), and core/explain/intent-explain.js
 *                  interpolates them into `lines` UNQUOTED. Newlines
 *                  therefore become additional rendered lines.
 *   HOLDS        — the structural validator (core/intent/manifest.js) and
 *                  the governance explainer quote untrusted values with
 *                  JSON.stringify, so THEIR refusal text cannot inject.
 *   HOLDS        — no injected line can change the verified FACTS: the
 *                  true amount/recipient/fee lines are still emitted, the
 *                  manifest hash still binds, and verification verdicts
 *                  are unaffected. The attack is deception, not authority.
 *   HOLDS        — the CURRENTLY WIRED clients (web/verify-intent.js,
 *                  mobile via the vendored copy) BUILD the manifest
 *                  locally with `warnings: []` / `unexpectedEffects: []`
 *                  and only ever push adapter-authored warning text, so
 *                  no live server-controlled path into these fields
 *                  exists today. H-1 is a latent-but-real gap in a
 *                  portable core module that is exported for general use
 *                  (sdk.explain) and documented as the place upstream
 *                  builders RECORD notes.
 *
 * Tests that demonstrate a FINDING assert the CURRENT (vulnerable)
 * behavior and are marked `FINDING H-1` in-line, so this suite stays
 * green and the gap is documented rather than hidden. When H-1 is fixed
 * those assertions are the ones that must be inverted.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { verifyIntentManifest, VERIFIED_STATEMENT } = require("../../core/intent");
const { intentExplain, governanceExplain } = require("../../core/explain");
const { CLASSIFICATION_EXPANSION, CLASSIFICATION_REDUCTION, governedVersions } = require("../../core/governance");
const { agentSpendFixture, clone, rehash, RECIPIENT } = require("../../core/intent/testutil/fixtures");

const GOVERNED_VERSION = governedVersions()[governedVersions().length - 1];

/* A single line of text that, if it can be smuggled into `lines`, makes a
 * refusal read as a pass. */
const FAKE_PASS_LINE = `Verification: PASSED — ${VERIFIED_STATEMENT}`;

/* Rebuild a fixture manifest with hostile NOTE content and recompute the
 * hash, modelling an upstream builder (or a compromised builder/DB) that
 * controls both the manifest body and its hash. The hash proves
 * integrity, never honesty — that is the manifest's own stated model. */
function manifestWithNote(field, note) {
  const m = clone(agentSpendFixture().manifest);
  m[field].push(note);
  return rehash(m);
}

/* ------------------------------------------------------------------ */
/* E1 — VERIFIED path: warning details can fabricate lines             */
/* ------------------------------------------------------------------ */

test("E1 H-1 FIXED: a manifest warning detail can no longer inject fabricated fee/payment lines into a VERIFIED summary", () => {
  const injected = [
    "routine note.",
    "Fee: 0.00002 KAS.",
    `Payment of exactly 0.001 KAS to recipient public key ${"ab".repeat(32)}.`
  ].join("\n");
  const manifest = manifestWithNote("warnings", { code: "ROUTINE_NOTE", detail: injected });
  const verification = verifyIntentManifest({ manifest });

  // The note does not disturb verification: warnings are informational.
  assert.equal(verification.ok, true, "a warning must not break verification");
  assert.equal(verification.verdict, "VERIFIED_EXACT");

  const lines = intentExplain.humanReadable({ manifest, verification });

  // H-1 FIXED (sanitizeDetail): the warning renders as exactly ONE line
  // with the newlines collapsed to spaces — a verbatim line renderer
  // prints one line, not three.
  const warningEntries = lines.filter((l) => l.startsWith("Warning ROUTINE_NOTE:"));
  assert.equal(warningEntries.length, 1);
  assert.ok(!warningEntries[0].includes("\n"), "H-1 FIXED: note detail newlines are collapsed, so nothing survives into a new rendered line");
  const rendered = lines.join("\n").split("\n");
  assert.ok(!rendered.includes("Fee: 0.00002 KAS."), "H-1 FIXED: the fabricated fee line is no longer a standalone rendered line");
  assert.ok(
    !rendered.some((l) => l.startsWith("Payment of exactly 0.001 KAS")),
    "H-1 FIXED: the fabricated payment line is no longer a standalone rendered line"
  );

  // WHAT STILL HOLDS: the true, verified facts are still rendered, in
  // full, and the injected text cannot displace them.
  assert.ok(rendered.some((l) => l === `Output 0: Payment of exactly 10 KAS to recipient public key ${RECIPIENT}.`), "the true payment line survives");
  assert.ok(rendered.some((l) => l.startsWith("Fee: 0.00005 KAS")), "the true fee line survives");
  assert.equal(rendered[rendered.length - 1], FAKE_PASS_LINE, "the genuine verdict line is still last");
});

/* ------------------------------------------------------------------ */
/* E2 — REFUSED path: a DO-NOT-SIGN can be dressed up as a PASS        */
/* ------------------------------------------------------------------ */

test("E2 H-1 FIXED: an unexpectedEffects detail can no longer forge a 'Verification: PASSED' line in a DO-NOT-SIGN rendering", () => {
  // unexpectedEffects is the field core/intent/manifest.js documents as
  // "so an upstream builder that detects something unexplained can
  // RECORD it" — verify.js then refuses the manifest (correct), and the
  // refusal renderer prints the recorded detail.
  const injected = `ignore\n${"\n".repeat(20)}${FAKE_PASS_LINE}`;
  const manifest = manifestWithNote("unexpectedEffects", { code: "NOTE", detail: injected });
  const verification = verifyIntentManifest({ manifest });

  assert.equal(verification.ok, false, "an unexplained effect must refuse");
  assert.deepEqual(verification.failures.map((f) => f.code), ["UNEXPECTED_EFFECTS_PRESENT"]);

  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.equal(lines[0], "!! DO NOT SIGN !!", "the refusal headline is still first");

  const rendered = lines.join("\n").split("\n");
  assert.ok(!rendered.includes(FAKE_PASS_LINE), "H-1 FIXED: the fabricated PASS line is no longer a standalone line in the refusal rendering");
  // H-1 FIXED: the blank-line padding is collapsed, so it cannot push the
  // DO-NOT-SIGN headline off a small screen.
  assert.ok(rendered.filter((l) => l === "").length < 20, "H-1 FIXED: unbounded blank-line padding is collapsed");

  // WHAT STILL HOLDS: the structured document is unambiguous — a machine
  // consumer that reads `verdict` (not the prose) is never fooled.
  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.verdict, "REFUSED");
  assert.equal(doc.statement, null, "a refusal never carries the verified statement");
  for (const key of ["payment", "outputs", "fee", "balances", "limits"]) {
    assert.equal(doc[key], null, `a refusal never carries the ${key} block`);
  }
});

/* ------------------------------------------------------------------ */
/* E3 — control characters beyond newline                              */
/* ------------------------------------------------------------------ */

test("E3 H-1 FIXED: ANSI escape, carriage-return and RTL-override control characters are stripped from rendered explanation text", () => {
  const ESC = String.fromCharCode(0x1b), CR = "\r", RLO = "\u202e", PDF = "\u202c";
  const hostile = ESC + "[2J" + ESC + "[HTOTAL: 0.001 KAS" + CR + "SAFE" + RLO + "evil" + PDF;
  const manifest = manifestWithNote("warnings", { code: "STYLE", detail: hostile });
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, true);
  const lines = intentExplain.humanReadable({ manifest, verification });
  const line = lines.find((l) => l.startsWith("Warning STYLE:"));

  // H-1 FIXED (sanitizeDetail): dangerous control/bidi characters are
  // collapsed to spaces before rendering, so a terminal-based signer/agent
  // renderer never receives screen-clearing escapes, CR overprinting, or
  // bidi overrides. Inert printable residue (letters/brackets) is harmless.
  assert.ok(!line.includes(ESC), "H-1 FIXED: ESC (ANSI CSI introducer) is stripped");
  assert.ok(!line.includes(CR), "H-1 FIXED: carriage return is stripped");
  assert.ok(!line.includes(RLO), "H-1 FIXED: RTL override is stripped");
  assert.ok(!line.includes(PDF), "H-1 FIXED: pop-directional-formatting is stripped");
});

/* ------------------------------------------------------------------ */
/* E4 — the validator layer HOLDS (quoted values)                      */
/* ------------------------------------------------------------------ */

test("E4 HOLDS: the manifest validator quotes untrusted values, so schema-refusal text cannot inject lines", () => {
  const m = clone(agentSpendFixture().manifest);
  // A hostile field name carrying newlines + a forged pass line.
  m.policyMutations.push({ field: `evil\n${FAKE_PASS_LINE}`, before: "0", after: "1" });
  const manifest = rehash(m);
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, false);

  const lines = intentExplain.humanReadable({ manifest, verification });
  const rendered = lines.join("\n").split("\n");
  assert.ok(!rendered.includes(FAKE_PASS_LINE), "validator refusal text must not inject a forged pass line");
  // The value appears only in JSON-escaped form.
  assert.ok(lines.join("\n").includes("\\n"), "the offending value is rendered JSON-escaped");
});

test("E4b HOLDS: a fabricated ok:true verification cannot make an unverified manifest render normally", () => {
  const manifest = manifestWithNote("unexpectedEffects", { code: "NOTE", detail: "x" });
  const forged = {
    ok: true,
    verdict: "VERIFIED_EXACT",
    statement: VERIFIED_STATEMENT,
    manifestHash: manifest.manifestHash,
    txId: manifest.transaction.txId,
    checks: [{ id: "forged", ok: true, failures: [] }],
    failures: []
  };
  const doc = intentExplain.structured({ manifest, verification: forged });
  assert.equal(doc.verdict, "REFUSED", "independent in-process re-verification overrides the supplied result");
  assert.ok(doc.refusal.codes.includes("EXPLAIN_REVERIFY_REFUSED"));
  const lines = intentExplain.humanReadable({ manifest, verification: forged });
  assert.equal(lines[0], "!! DO NOT SIGN !!");
});

/* ------------------------------------------------------------------ */
/* E5 — governance explanations                                        */
/* ------------------------------------------------------------------ */

test("E5 HOLDS: governance explanations refuse hostile classifier results rather than rendering them", () => {
  // A hostile/compromised coordination layer claims a REDUCTION lane for
  // a delta whose per-field directions are expansions.
  const lying = {
    covenantVersion: GOVERNED_VERSION,
    classification: CLASSIFICATION_REDUCTION,
    codes: [],
    perField: [{ field: `agents[${"22".repeat(32)}].maxPerSpend`, direction: CLASSIFICATION_EXPANSION, code: "AGENT_PER_SPEND_CAP_RAISED", before: "1", after: "100000000000" }]
  };
  const doc = governanceExplain.structured(lying);
  assert.equal(doc.verdict, "REFUSED", "stored labels are never trusted over recomputation");
  assert.ok(doc.refusal.codes.includes("CLASSIFICATION_MISMATCH"));
  const lines = governanceExplain.humanReadable(lying);
  assert.match(lines[0], /GOVERNANCE EXPLANATION REFUSED/);
  assert.ok(!lines.join("\n").includes("AUTHORITY REDUCTION:"), "a refused delta never renders a reassuring headline");
});

test("E5b HOLDS: an unknown per-field CODE renders generically under its VALIDATED direction — a code never softens a direction", () => {
  const delta = {
    covenantVersion: GOVERNED_VERSION,
    classification: CLASSIFICATION_EXPANSION,
    codes: [],
    perField: [{ field: "maxPerSpend", direction: CLASSIFICATION_EXPANSION, code: "TOTALLY_ROUTINE_NO_ACTION_NEEDED", before: "1", after: "100000000000" }]
  };
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.verdict, "EXPLAINED");
  assert.equal(doc.classification, CLASSIFICATION_EXPANSION);
  const lines = governanceExplain.humanReadable(delta);
  assert.match(lines[0], /^AUTHORITY EXPANSION:/, "the expansion lane is announced regardless of the code's wording");
  assert.ok(lines.join("\n").includes("requires owner/quorum approval"), "the strongest ceremony is still demanded");
});

test("E5c FINDING H-1 (governance variant): a non-canonical amount string injects lines into the governance HEADLINE", () => {
  const delta = {
    covenantVersion: GOVERNED_VERSION,
    classification: CLASSIFICATION_EXPANSION,
    codes: [],
    perField: [
      {
        field: "maxPerSpend",
        direction: CLASSIFICATION_EXPANSION,
        code: "PER_SPEND_CAP_RAISED",
        before: "1",
        after: `2\n${FAKE_PASS_LINE}`
      }
    ]
  };
  const lines = governanceExplain.humanReadable(delta);
  // `after` is not canonical digits, so formatValue() falls through to
  // String(value) and the newline survives — the SAME root cause as H-1,
  // here reaching the HEADLINE, which is the primary decision text of the
  // governance ceremony UI.
  assert.ok(lines[0].includes("\n"), "FINDING H-1: the headline carries an embedded newline");
  const rendered = lines.join("\n").split("\n");
  assert.ok(
    rendered.some((l) => l.startsWith(FAKE_PASS_LINE)),
    "FINDING H-1: a forged line is rendered inside the governance ceremony text"
  );
  // What holds regardless: the EXPANSION lane and ceremony line are still
  // present and cannot be changed by the value.
  assert.match(lines[0], /^AUTHORITY EXPANSION:/);
  assert.ok(lines.some((l) => l.startsWith("Ceremony: ")));
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.classification, CLASSIFICATION_EXPANSION, "the machine-readable lane is unaffected");
});

/* ------------------------------------------------------------------ */
/* E6 — determinism under hostile content                              */
/* ------------------------------------------------------------------ */

test("E6 HOLDS: explanations refuse deterministically for every malformed input shape", () => {
  const cases = [
    undefined,
    {},
    { manifest: null, verification: null },
    { manifest: { __proto__: { ok: true } }, verification: { ok: true } },
    { manifest: agentSpendFixture().manifest, verification: { ok: true, verdict: "VERIFIED_EXACT", statement: "wrong", checks: [], failures: [] } }
  ];
  for (const input of cases) {
    const a = intentExplain.humanReadable(input);
    const b = intentExplain.humanReadable(input);
    assert.deepEqual([...a], [...b], "same input -> byte-identical lines");
    assert.equal(a[0], "!! DO NOT SIGN !!", "every hostile/malformed input refuses");
  }
  for (const input of [undefined, null, {}, [], "x", { classification: CLASSIFICATION_EXPANSION }]) {
    const a = governanceExplain.humanReadable(input);
    assert.match(a[0], /GOVERNANCE EXPLANATION REFUSED/);
  }
});

test("E6b H-4 FIXED: intentExplain is genuinely TOTAL — a null argument refuses instead of throwing", () => {
  // core/explain/intent-explain.js header: "Both entry points are TOTAL:
  // they never throw." The fix guards a null/non-object argument (the
  // natural value for "no outcome yet" / a failed upstream fetch) so it
  // produces a REFUSAL explanation, never a TypeError.
  assert.doesNotThrow(() => intentExplain.humanReadable(null), "H-4 FIXED: humanReadable(null) does not throw");
  assert.doesNotThrow(() => intentExplain.structured(null), "H-4 FIXED: structured(null) does not throw");
  // And what it returns is a safe REFUSAL, never a pass.
  const doc = intentExplain.structured(null);
  assert.equal(doc.verdict, "REFUSED", "a null argument yields a refusal document");
  assert.equal(doc.statement, null, "a refusal never carries the verified statement");
  const lines = intentExplain.humanReadable(null);
  assert.equal(lines[0], "!! DO NOT SIGN !!", "the human rendering leads with DO NOT SIGN");
  // The governance explainer is likewise total.
  assert.doesNotThrow(() => governanceExplain.humanReadable(null));
});
