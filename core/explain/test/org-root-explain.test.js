"use strict";

/*
 * UNIT: the v0.7 ORGANIZATIONAL ROOT explanation layer
 * (core/explain/org-root-explain.js).
 *
 * The fixtures are REAL production-byte manifests captured from the v0.7 SDK
 * (sdk/tools/capture-v7-manifests.js, deterministic TEST-ONLY keys), so these
 * pure-core tests render exactly what an owner would be shown for a real
 * transaction — with no compiler or binary dependency here.
 *
 * Layers proven:
 *   - fixed-line GOLDENS (byte-identical rendering; no model text anywhere);
 *   - the root-outpoint kill switch is stated on EVERY verified rendering and
 *     no expiry is ever invented;
 *   - authority class, threshold, expected slots and every vault operation;
 *   - the recovery / succession warnings;
 *   - REFUSALS name the failing check, carry no rendered facts, and are TOTAL
 *     (a malformed input never throws and never renders as an approval);
 *   - amounts are BigInt-rendered exactly — no floats, no exponents, no
 *     truncated identities;
 *   - a forbidden-word scan: this layer never says "audited", "compliant" or
 *     "certified".
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const explain = require("../org-root-explain");
const { structured, humanReadable } = explain;
const { computeManifestHashV1 } = require("../../intent/canonical");
const { ORG_ROOT_MANIFEST_VERSION_1, ROOTED_VAULT_MANIFEST_VERSION_1 } = require("../../intent/org-root-manifest-v7");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "v7-org-root-manifests.json");
const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
const byName = new Map(fixture.manifests.map((m) => [m.name, m]));

function render(name) {
  const f = byName.get(name);
  assert.ok(f, `fixture ${name} is missing — regenerate with sdk/tools/capture-v7-manifests.js`);
  return { doc: structured({ manifest: f.manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts }), lines: humanReadable({ manifest: f.manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts }) };
}

/* deep clone + re-hash so a tamper row exercises the SEMANTIC check rather
 * than only the hash check (which is asserted on its own). */
function tamper(manifest, mutate) {
  const { manifestHash, ...body } = JSON.parse(JSON.stringify(manifest));
  void manifestHash;
  mutate(body);
  return { ...body, manifestHash: computeManifestHashV1(body) };
}

const DOC_KEYS = [
  "explanationVersion",
  "verdict",
  "statement",
  "refusal",
  "context",
  "manifestHash",
  "txId",
  "network",
  "organization",
  "authorization",
  "quorum",
  "ownerSet",
  "rootState",
  "timeLock",
  "freshness",
  "fee",
  "vaultOperations",
  "warnings",
  "verification"
];

/* ------------------------------------------------------------------ */

test("org-root explain: every captured production manifest renders VERIFIED_EXACT on ONE closed document shape", () => {
  assert.ok(fixture.manifests.length >= 11, `expected the full capture, got ${fixture.manifests.length}`);
  for (const f of fixture.manifests) {
    const doc = structured({ manifest: f.manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts }); // Codex checkpoint 6: the request-carried predecessor redeem scripts
    assert.equal(doc.verdict, "VERIFIED_EXACT", `${f.name}: ${JSON.stringify(doc.refusal)}`);
    assert.equal(doc.explanationVersion, "policyvault-org-root-explanation/1");
    assert.deepEqual(Object.keys(doc), DOC_KEYS, `${f.name}: the document key set must be closed and stable`);
    assert.equal(doc.refusal, null);
    assert.equal(doc.statement, "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.");
    assert.equal(doc.verification.verdict, "VERIFIED");
    assert.deepEqual(doc.verification.failingChecks, []);
  }
});

test("org-root explain: the ROOT OUTPOINT KILL SWITCH is stated on every verified rendering and no expiry is ever invented", () => {
  for (const f of fixture.manifests) {
    const { doc, lines } = render(f.name);
    assert.equal(doc.freshness.kind, "ROOT_OUTPOINT_KILL_SWITCH");
    assert.equal(doc.freshness.expiry, null, `${f.name}: an expiry would be security theatre — lockTime is a lower bound only`);
    assert.deepEqual(doc.freshness.rootOutpoint, doc.organization.rootOutpoint);
    assert.ok(lines.includes(explain.ROOT_OUTPOINT_KILL_SWITCH_LINE), `${f.name}: the kill-switch line must be rendered verbatim`);
    assert.match(explain.ROOT_OUTPOINT_KILL_SWITCH_LINE, /valid only while this root UTXO is unspent; no expiry/);
    for (const line of lines) {
      assert.doesNotMatch(line, /expires? (at|on)|valid until|deadline/i, `${f.name}: no expiry language may appear: ${line}`);
    }
  }
});

test("org-root explain GOLDEN: a plain AUTHORIZE renders these exact lines", () => {
  const { lines } = render("root_authorize_2of3");
  assert.deepEqual(lines, [
    "ORGANIZATION ROOT APPROVAL — authorize (AUTHORITY-NEUTRAL).",
    "You are being asked to authorize: AUTHORIZE — the owner quorum authorizes the vault operations listed in this transaction. The owner set, the thresholds and the freeze flag are all carried across unchanged; only the root nonce advances.",
    "Organization a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7; root covenant 5252525252525252525252525252525252525252525252525252525252525252.",
    "Root outpoint being spent: 0101010101010101010101010101010101010101010101010101010101010101:0.",
    "Freshness: valid only while this root UTXO is unspent; no expiry. Spending the root outpoint invalidates every collected approval at once.",
    "Threshold: 2 of 3 active owner slot(s) must sign (from ownerM); collected so far: 2.",
    "Expected signer — slot 1: 7171717171717171717171717171717171717171717171717171717171717171",
    "Expected signer — slot 2: 7272727272727272727272727272727272727272727272727272727272727272",
    "Expected signer — slot 3: 7373737373737373737373737373737373737373737373737373737373737373",
    "Owner set before: 2-of-3 (emergency quorum 1, recovery quorum 2).",
    "Owner set after: 2-of-3 (emergency quorum 1, recovery quorum 2).",
    "Owner keys: unchanged by this transaction.",
    "Freeze flag: 0 -> 0. Root nonce advances 0 -> 1.",
    "Root state digest before: 33f8d90ff3e176e65d673a87670fb15726c7beab987e2b15fe983abf8f711704",
    "Root state digest after: 1c26dd121ceebf1bf02d72959bfa98e6754553749f01d52a3aa0dba3c3235d84",
    "Network fee: 0.026366 KAS. The root holds 3 KAS and keeps 3 KAS (loses 0 KAS; the covenant caps this at 0.002 KAS per transition).",
    "Vault operations in this transaction: none — this transaction only moves the root.",
    "Network: testnet-10. Contract: policyvault-0.7-root.",
    "Transaction id: e241b107fd882716a73f131545d81b7049a829830e85330e4f73b5398b5765af. Manifest hash: f386f1a17eb580d30fdb275183727ed42aade5b47ccb79234f0b644645114e23.",
    "Verification: PASSED — AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY."
  ]);
});

test("org-root explain: the AUTHORITY CLASS, quorum source and expected slots come from the action table", () => {
  const rows = [
    ["root_authorize_2of3", "authorize", "AUTHORITY-NEUTRAL", "ownerM", "2", 3, null],
    ["root_rotate_installs_new_set", "rotate", "AUTHORITY-EXPANDING", "ownerM", "2", 3, null],
    ["root_freeze_emergency_quorum", "freeze", "AUTHORITY-REDUCING", "emergencyK", "1", 3, null],
    ["root_unfreeze_full_quorum", "unfreeze", "AUTHORITY-EXPANDING", "ownerM", "2", 3, null],
    ["root_owner_recover_lands_frozen", "ownerRecover", "AUTHORITY-EXPANDING", "recoveryM", "2", 3, null],
    ["root_succession", "succession", "AUTHORITY-EXPANDING", "successorPk", "1", 0, "TERMINAL"]
  ];
  for (const [name, action, klass, source, required, slotCount, previousSetClass] of rows) {
    const { doc, lines } = render(name);
    assert.equal(doc.authorization.actionName, action);
    assert.equal(doc.authorization.authorityClass, klass);
    assert.equal(doc.authorization.authorityClassForPreviousSet, previousSetClass);
    assert.equal(doc.quorum.quorumSource, source);
    assert.equal(doc.quorum.requiredApprovals, required);
    assert.equal(doc.quorum.expectedSignerSlots.length, slotCount, `${name}: expected slot count`);
    assert.equal(lines[0], `ORGANIZATION ROOT APPROVAL — ${action} (${klass}).`);
    assert.ok(lines.some((l) => l.startsWith(`Threshold: ${required} of `)), `${name}: the threshold line`);
    if (slotCount === 0) {
      assert.ok(lines.some((l) => l.startsWith("Expected signers: none —")), `${name}: succession is authorized by the pinned successor key`);
    }
  }
});

test("org-root explain: succession and owner recovery carry the FROZEN + relative-idle-delay + new-set warnings", () => {
  const recover = render("root_owner_recover_lands_frozen");
  assert.deepEqual(
    recover.doc.warnings.map((w) => w.code),
    ["AUTHORITY_EXPANDING", "RECOVERY_INSTALLS_NEW_SET", "LANDS_FROZEN", "RELATIVE_AGE_GATE", "OWNER_SET_CHANGES", "THRESHOLDS_CHANGE"]
  );
  assert.equal(recover.doc.rootState.frozenAfter, "1");
  assert.equal(recover.doc.timeLock.kind, "RELATIVE_INPUT_AGE");
  assert.equal(recover.doc.timeLock.delayDaa, "1000");
  assert.equal(recover.doc.timeLock.minSequence, "1000");
  assert.ok(recover.lines.some((l) => l.startsWith("Relative idle delay: this transaction is only valid once the root UTXO has been unspent for at least 1000 DAA score")));
  assert.ok(recover.lines.some((l) => l.includes("must deliberately UNFREEZE with their own approval quorum")), "the LANDS_FROZEN warning must state the unfreeze requirement");

  const succession = render("root_succession");
  assert.deepEqual(
    succession.doc.warnings.map((w) => w.code),
    ["AUTHORITY_EXPANDING", "SUCCESSION_TERMINAL_FOR_PREVIOUS_SET", "LANDS_FROZEN", "RELATIVE_AGE_GATE", "OWNER_SET_CHANGES", "THRESHOLDS_CHANGE"]
  );
  assert.equal(succession.doc.timeLock.delayDaa, "2000");
  assert.ok(succession.lines.some((l) => l.includes("A previous owner keeps authority only if that key is listed again")));

  /* an organization that opted OUT of both recovery paths is TOLD so */
  const none = render("root_authorize_no_recovery_no_succession");
  assert.deepEqual(none.doc.warnings.map((w) => w.code), ["RECOVERY_DISABLED", "SUCCESSION_DISABLED"]);
  assert.equal(none.doc.organization.recoveryEnabled, false);
  assert.equal(none.doc.organization.successionEnabled, false);
  assert.equal(none.doc.timeLock, null);

  /* the emergency (lighter) quorum is called out wherever it is used */
  const freeze = render("root_freeze_emergency_quorum");
  assert.ok(freeze.doc.warnings.some((w) => w.code === "EMERGENCY_QUORUM"));
  assert.ok(freeze.lines.some((l) => l.includes("Warning EMERGENCY_QUORUM:")));
});

test("org-root explain: each vault operation gets its own explanation, including the pinned recovery destination", () => {
  const pause = render("vault_owner_pause_under_authorize");
  assert.equal(pause.doc.vaultOperations.length, 1);
  const v = pause.doc.vaultOperations[0];
  assert.equal(v.sdkAction, "ownerPause");
  assert.equal(v.mutationClass, "AUTHORITY-REDUCING");
  assert.equal(v.requiredRootAction, "authorize");
  assert.equal(v.expectFrozenAfter, "0");
  assert.equal(v.terminal, false);
  assert.equal(v.orgRootCovenantId, pause.doc.organization.rootCovenantId);
  assert.ok(pause.lines.some((l) => l === "Vault operations in this transaction: 1. All of them happen together, or none of them do."));
  assert.ok(pause.lines.some((l) => l.startsWith("Vault operation 1: ownerPause on vault ")));

  const emergency = render("vault_emergency_pause_under_freeze");
  assert.equal(emergency.doc.vaultOperations[0].requiredRootAction, "freeze");
  assert.equal(emergency.doc.vaultOperations[0].expectFrozenAfter, "1");

  const terminal = render("vault_recover_terminal_with_position");
  const t = terminal.doc.vaultOperations[0];
  assert.equal(t.terminal, true);
  assert.equal(t.mutationClass, "TERMINAL");
  assert.equal(t.recoveryPk, "5151515151515151515151515151515151515151515151515151515151515151");
  assert.equal(t.token.positionBefore.atomic, "300");
  assert.equal(t.token.positionAfter.atomic, "0");
  assert.equal(t.token.positionBefore.display, "3.00", "atomic units render with the DISPLAY-ONLY decimals of the descriptor");
  assert.ok(terminal.lines.some((l) => l.includes("TERMINAL: this vault is CLOSED. Payout 5 KAS to the genesis-pinned recovery key 5151515151515151515151515151515151515151515151515151515151515151.")));
  assert.ok(terminal.doc.warnings.some((w) => w.code === "TERMINAL_VAULT_OPERATION"));
});

test("org-root explain: a TAMPERED manifest is REFUSED and the failing check is NAMED", () => {
  const base = byName.get("vault_recover_terminal_with_position");
  const descriptors = base.descriptors;
  const rows = [
    ["bare hash edit", { ...base.manifest, manifestHash: "ee".repeat(32) }, "manifestHash"],
    ["root outpoint substituted", tamper(base.manifest, (m) => {
      m.root.outpoint = { transactionId: "0e".repeat(32), index: 0 };
      m.freshness.rootOutpoint = { transactionId: "0e".repeat(32), index: 0 };
    }), "rootOutpointBinding"],
    ["action relabelled", tamper(base.manifest, (m) => {
      m.action.name = "freeze";
      m.action.code = 2;
      m.action.authorityClass = "AUTHORITY-REDUCING";
      m.action.quorumSource = "emergencyK";
    }), "frozenOutcome"],
    ["authority class softened", tamper(base.manifest, (m) => { m.action.authorityClass = "AUTHORITY-REDUCING"; }), "actionTable"],
    ["threshold understated", tamper(base.manifest, (m) => { m.action.requiredApprovals = "1"; }), "requiredApprovals"],
    ["quorum claimed satisfied below the requirement", tamper(base.manifest, (m) => { m.action.satisfiedApprovals = "1"; }), "quorumSatisfied"],
    ["expected slot set truncated", tamper(base.manifest, (m) => { m.action.expectedSignerSlots = m.action.expectedSignerSlots.slice(0, 1); }), "expectedSignerSlots"],
    ["successor tail forged", tamper(base.manifest, (m) => { m.rootState.after.tailHex = "010008ff00000000000000"; }), "successorTailBytes"],
    ["nonce not advanced", tamper(base.manifest, (m) => { m.rootState.after.state.rootNonce = m.rootState.before.state.rootNonce; }), "nonceAdvancesByOne"],
    ["fee understated", tamper(base.manifest, (m) => { m.fee.requiredFeeSompi = "1"; }), "feeExact"],
    ["root value loss understated", tamper(base.manifest, (m) => { m.fee.rootValueLoss = "999"; }), "rootValueRule"],
    ["vault pinned to a FOREIGN root", tamper(base.manifest, (m) => {
      m.vaultOperations[0].manifest.vault.orgRootCovenantId = "cc".repeat(32);
      const { manifestHash, ...body } = m.vaultOperations[0].manifest;
      void manifestHash;
      m.vaultOperations[0].manifest = { ...body, manifestHash: computeManifestHashV1(body) };
    }), "vaultOp[43434343]rootPin"]
  ];
  for (const [label, bad, expectedCheck] of rows) {
    const doc = structured({ manifest: bad, descriptors });
    const lines = humanReadable({ manifest: bad, descriptors });
    assert.equal(doc.verdict, "REFUSED", `${label}: must be REFUSED`);
    assert.ok(doc.refusal.failingChecks.includes(expectedCheck), `${label}: expected the failing check ${expectedCheck}, got [${doc.refusal.failingChecks.join(", ")}]`);
    assert.equal(doc.statement, null, `${label}: a refused explanation never carries the verified statement`);

    /* a refusal renders NO facts: no owner set, no amounts, no destinations */
    assert.equal(doc.quorum, null);
    assert.equal(doc.ownerSet, null);
    assert.equal(doc.fee, null);
    assert.equal(doc.vaultOperations, null);
    assert.equal(doc.warnings, null);

    assert.equal(lines[0], "!! DO NOT SIGN !!");
    assert.ok(lines.some((l) => l.startsWith("Failing checks: ")), `${label}: the failing checks are listed`);
    assert.ok(lines.some((l) => l.startsWith(`- ${expectedCheck}: `)), `${label}: the failing check is named on its own line`);
    assert.ok(lines.some((l) => l.includes("must not be signed")));
    assert.ok(!lines.some((l) => l.startsWith("Verification: PASSED")), `${label}: a refusal never renders a PASSED line`);
  }
  assert.equal(rows.length, 12);
});

test("org-root explain: a STANDALONE rooted-vault manifest refuses with verifyWithinParent (its authority IS the root input)", () => {
  const doc = structured({ manifest: fixture.standaloneRootedVaultManifest });
  assert.equal(doc.verdict, "REFUSED");
  assert.deepEqual(doc.refusal.failingChecks, ["verifyWithinParent"]);
  assert.equal(doc.context.manifestVersion, ROOTED_VAULT_MANIFEST_VERSION_1);
  assert.equal(doc.context.unverified, true);
  const lines = humanReadable({ manifest: fixture.standaloneRootedVaultManifest });
  assert.equal(lines[0], "!! DO NOT SIGN !!");
  assert.ok(lines.some((l) => l.includes("a rooted vault has NO owner key")));
});

test("org-root explain is TOTAL: unknown versions, malformed input and internal faults refuse instead of throwing", () => {
  const cases = [
    [undefined, "manifestSupplied"],
    [null, "manifestSupplied"],
    ["not an object", "manifestSupplied"],
    [42, "manifestSupplied"],
    [[], "manifestSupplied"],
    [{}, "manifestVersion"],
    [{ manifestVersion: "policyvault-org-root-manifest/2" }, "manifestVersion"],
    [{ manifestVersion: "policyvault-token-intent-manifest/1" }, "manifestVersion"]
  ];
  for (const [manifest, expected] of cases) {
    const doc = structured({ manifest });
    assert.equal(doc.verdict, "REFUSED", `${JSON.stringify(manifest)}`);
    assert.ok(doc.refusal.failingChecks.includes(expected), `${JSON.stringify(manifest)}: got [${doc.refusal.failingChecks.join(", ")}]`);
    const lines = humanReadable({ manifest });
    assert.equal(lines[0], "!! DO NOT SIGN !!");
  }
  /* the entry points tolerate a missing/!object argument entirely */
  assert.equal(structured().verdict, "REFUSED");
  assert.equal(structured(null).verdict, "REFUSED");
  assert.equal(humanReadable()[0], "!! DO NOT SIGN !!");

  /* a structurally-valid manifest whose body is internally broken refuses,
   * never throws (the verifier's own exception path is surfaced by name) */
  const broken = { ...byName.get("root_authorize_2of3").manifest, rootState: { before: { digest: "00".repeat(32), state: null }, after: { digest: "00".repeat(32), state: null, tailHex: "00" } } };
  const doc = structured({ manifest: broken });
  assert.equal(doc.verdict, "REFUSED");
  assert.ok(doc.refusal.failingChecks.length > 0);
});

test("org-root explain: amounts are exact BigInt renderings — no floats, no exponents, no truncated identities", () => {
  for (const f of fixture.manifests) {
    const { doc, lines } = render(f.name);
    /* the fee block carries the exact integer AND its exact KAS rendering */
    assert.equal(doc.fee.networkFee.sompi, f.manifest.fee.requiredFeeSompi);
    assert.equal(doc.fee.rootValueBefore.sompi, f.manifest.root.valueBefore);
    assert.equal(doc.fee.rootValueAfter.sompi, f.manifest.root.valueAfter);
    assert.equal(doc.fee.rootValueLoss.sompi, f.manifest.fee.rootValueLoss);
    for (const line of lines) {
      assert.doesNotMatch(line, /[0-9]e[+-][0-9]/i, `${f.name}: exponent notation in a rendered line: ${line}`);
      assert.doesNotMatch(line, /\bNaN\b|\bInfinity\b|undefined|\[object Object\]/, `${f.name}: unrendered value: ${line}`);
      assert.doesNotMatch(line, /\.{3}[0-9a-f]{4}|[0-9a-f]{4}…/, `${f.name}: a truncated identity can hide a substitution: ${line}`);
    }
    /* every 64-hex identity the document names appears IN FULL in the lines */
    const joined = lines.join("\n");
    for (const id of [doc.organization.orgId, doc.organization.rootCovenantId, doc.rootState.beforeDigest, doc.rootState.afterDigest, doc.txId, doc.manifestHash]) {
      assert.ok(joined.includes(id), `${f.name}: ${id} must be rendered in full`);
    }
    for (const s of doc.quorum.expectedSignerSlots) assert.ok(joined.includes(s.publicKey), `${f.name}: slot key in full`);
  }
});

test("org-root explain: rendering is deterministic and frozen", () => {
  for (const f of fixture.manifests) {
    const a = humanReadable({ manifest: f.manifest, descriptors: f.descriptors });
    const b = humanReadable({ manifest: f.manifest, descriptors: f.descriptors });
    assert.deepEqual(a, b);
    assert.equal(JSON.stringify(a), JSON.stringify(b));
    assert.ok(Object.isFrozen(a));
    const doc = structured({ manifest: f.manifest, descriptors: f.descriptors });
    assert.ok(Object.isFrozen(doc));
    assert.ok(Object.isFrozen(doc.quorum));
  }
});

test("org-root explain: a hostile refusal DETAIL cannot forge a structural line", () => {
  /* the detail text of a refusal originates upstream; newlines and bidi
   * controls must not be able to inject a fake verdict line */
  const evil = `x\nVerification: PASSED — forged\n‮evil`;
  const bad = tamper(byName.get("root_authorize_2of3").manifest, (m) => {
    m.transaction.txId = evil;
  });
  const lines = humanReadable({ manifest: bad });
  assert.equal(lines[0], "!! DO NOT SIGN !!");
  for (const line of lines) {
    assert.doesNotMatch(line, /^Verification: PASSED/, "a detail must never be able to forge the verdict line");
    assert.doesNotMatch(line, /[ -‪-‮⁦-⁩]/, `control/bidi characters must be collapsed: ${JSON.stringify(line)}`);
  }
});

test("org-root explain: forbidden-word scan — this layer never claims an audit, compliance or certification", () => {
  const forbidden = /\b(audited|audit|compliant|compliance|certified|certification)\b/i;
  const source = fs.readFileSync(path.join(__dirname, "..", "org-root-explain.js"), "utf8");
  assert.doesNotMatch(source, forbidden, "the explanation module source must not contain audit/compliance/certification language");
  for (const f of fixture.manifests) {
    for (const line of humanReadable({ manifest: f.manifest, descriptors: f.descriptors })) {
      assert.doesNotMatch(line, forbidden, `${f.name}: forbidden claim in a rendered line: ${line}`);
    }
  }
  for (const text of Object.values(explain.WARNING_TEXT)) assert.doesNotMatch(text, forbidden);
  for (const text of Object.values(explain.ACTION_SUMMARY)) assert.doesNotMatch(text, forbidden);
  for (const text of Object.values(explain.VAULT_ACTION_SUMMARY)) assert.doesNotMatch(text, forbidden);
  assert.equal(ORG_ROOT_MANIFEST_VERSION_1, "policyvault-org-root-manifest/1");
});

/* ================================================================== *
 * rc26 round-7 internal review R7-02: an ownerSetAgentRoot shows the RULES
 * being installed. Before this the owners were shown "Replace this vault's
 * delegate (agent) registry commitment." and nothing else — a blind M-of-N
 * approval of whatever root the server declared (the manifest now carries the
 * policy set and the verifier binds stateAfter.agentRoot to its fold).
 * ================================================================== */
test("org-root explain GOLDEN (R7-02): an ownerSetAgentRoot renders EVERY policy of the new delegate set — the rules the owners install", () => {
  const { doc, lines } = render("vault_set_agent_root_under_authorize");
  assert.equal(doc.verdict, "VERIFIED_EXACT");
  const v = doc.vaultOperations[0];
  assert.equal(v.sdkAction, "ownerSetAgentRoot");
  assert.equal(v.agentSet.length, 2, "both installed policies are in the structured document");
  assert.deepEqual(v.agentSet.map((p) => p.agentPk), ["62".repeat(32), "66".repeat(32)]);
  assert.equal(v.agentSet[0].tokenMaxPerSpend.atomic, "100");
  assert.equal(v.agentSet[1].tokenMaxPerSpend.atomic, "250");
  assert.equal(v.agentSet[0].agentMaxFeePerTx.kas, "1");
  assert.equal(v.agentSet[0].agentMaxCarryKas.kas, "0.25");
  const i = lines.indexOf("Vault operation 1: ownerSetAgentRoot on vault 4444444444444444444444444444444444444444444444444444444444444444 (covenant 4343434343434343434343434343434343434343434343434343434343434343).");
  assert.ok(i > 0, "the vault operation header line");
  assert.deepEqual(lines.slice(i, i + 13), [
    "Vault operation 1: ownerSetAgentRoot on vault 4444444444444444444444444444444444444444444444444444444444444444 (covenant 4343434343434343434343434343434343434343434343434343434343434343).",
    "  Replace this vault's delegate (agent) registry commitment.",
    "  Authority: AUTHORITY-EXPANDING; this operation requires the root to run authorize.",
    "  This vault is pinned to root covenant 5252525252525252525252525252525252525252525252525252525252525252.",
    "  Asset: Org Treasury Token (assetId 1111111111111111111111111111111111111111111111111111111111111111, descriptor 199fe235ce0f228d810eb84add5f15ec1b21478aae7d3db33ab323e273a2fc1f).",
    "  No declared issuer powers (declared-only; PolicyVault cannot discover undeclared powers).",
    "  Fee reserve: 5 KAS -> 5 KAS (consumed 0 KAS).",
    "  New delegate policy set (2 policies) — these are the RULES being installed; the successor agentRoot is their Merkle root:",
    "    agent 6262626262626262626262626262626262626262626262626262626262626262: per-spend cap 100, period budget 400 per 1000 DAA (period starts 5000, spent so far 0), fee cap 1 KAS per transaction, KAS carry cap 0.25 KAS.",
    "      may pay ONLY these 1 recipient(s): 6363636363636363636363636363636363636363636363636363636363636363",
    "    agent 6666666666666666666666666666666666666666666666666666666666666666: per-spend cap 250, period budget 400 per 1000 DAA (period starts 5000, spent so far 0), fee cap 1 KAS per transaction, KAS carry cap 0.25 KAS.",
    "      may pay ONLY these 1 recipient(s): 6363636363636363636363636363636363636363636363636363636363636363",
    "  Vault policy nonce advances 0 -> 1."
  ]); // Codex checkpoint 11 (R7-02): the recipients each policy may pay are RENDERED (STRICTER golden: +2 lines; the opaque "recipient allowlist root" suffix is gone)
  /* every other operation carries no agentSet (closed document shape unchanged) */
  for (const f of fixture.manifests) {
    if (f.name === "vault_set_agent_root_under_authorize") continue;
    const d = structured({ manifest: f.manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts });
    for (const op of d.vaultOperations) assert.equal(op.agentSet, null, `${f.name}: agentSet is null for ${op.sdkAction}`);
  }
});

test("org-root explain (R7-02): a substituted or withheld policy set is REFUSED by name — never rendered as an approval", () => {
  const f = byName.get("vault_set_agent_root_under_authorize");
  const rehashInner = (m) => { const { manifestHash, ...body } = m.vaultOperations[0].manifest; void manifestHash; m.vaultOperations[0].manifest = { ...body, manifestHash: computeManifestHashV1(body) }; };
  const cases = [
    ["per-spend cap of the first policy raised to 10^9 (declared root kept)", (m) => { m.vaultOperations[0].manifest.policy.agentSet[0].tokenMaxPerSpend = "1000000000"; rehashInner(m); }, "agentSetBound"],
    ["the policy set withheld", (m) => { delete m.vaultOperations[0].manifest.policy.agentSet; rehashInner(m); }, "agentSetPresent"],
    ["stateAfter.agentRoot substituted (set kept)", (m) => { m.vaultOperations[0].manifest.stateAfter.state.agentRoot = "99".repeat(32); rehashInner(m); }, "agentSetBound"]
  ];
  for (const [label, mutate, check] of cases) {
    const tampered = tamper(f.manifest, mutate);
    const doc = structured({ manifest: tampered, descriptors: f.descriptors, redeemScripts: f.redeemScripts });
    assert.equal(doc.verdict, "REFUSED", label);
    assert.ok(doc.refusal.failingChecks.some((c) => c.endsWith(check)), `${label}: expected ${check}, got ${doc.refusal.failingChecks.join(",")}`);
    const lines = humanReadable({ manifest: tampered, descriptors: f.descriptors, redeemScripts: f.redeemScripts });
    assert.equal(lines[0], "!! DO NOT SIGN !!");
    assert.ok(!lines.some((l) => /New delegate policy set/.test(l)), `${label}: a refusal renders no policy lines`);
  }
});

test("org-root explain GOLDEN (R7-02, checkpoint 11): the setAgentRoot review lists every RECIPIENT each installed policy may pay — never only an opaque allowlist root", () => {
  const { doc, lines } = render("vault_set_agent_root_under_authorize");
  const v = doc.vaultOperations[0];
  for (const p of v.agentSet) {
    assert.ok(Array.isArray(p.recipients) && p.recipients.length === 1, "the structured document lists the recipients");
    assert.equal(p.recipients[0], "63".repeat(32));
  }
  const i = lines.findIndex((l) => /New delegate policy set \(2 policies\)/.test(l));
  assert.ok(i > 0);
  assert.deepEqual(lines.slice(i + 1, i + 5), [
    "    agent 6262626262626262626262626262626262626262626262626262626262626262: per-spend cap 100, period budget 400 per 1000 DAA (period starts 5000, spent so far 0), fee cap 1 KAS per transaction, KAS carry cap 0.25 KAS.",
    "      may pay ONLY these 1 recipient(s): 6363636363636363636363636363636363636363636363636363636363636363",
    "    agent 6666666666666666666666666666666666666666666666666666666666666666: per-spend cap 250, period budget 400 per 1000 DAA (period starts 5000, spent so far 0), fee cap 1 KAS per transaction, KAS carry cap 0.25 KAS.",
    "      may pay ONLY these 1 recipient(s): 6363636363636363636363636363636363636363636363636363636363636363"
  ]);
  assert.ok(!lines.some((l) => /recipient allowlist root/.test(l)), "no opaque-root-only line remains");
});
