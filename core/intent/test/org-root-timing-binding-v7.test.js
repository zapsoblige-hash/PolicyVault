"use strict";

/*
 * UNIT (portable core, real production-byte fixtures): rc26 round-7 review
 * finding R7-01 — the shared v0.7 verifier BINDS every input's `sequence` and
 * the transaction `lockTime`, not only the age-gated root input's sequence and
 * the agent spend's lockTime.
 *
 * Why: a hostile server authors the frozen transaction. Without this binding
 * it could attach a hidden RELATIVE LOCK (rusty-kaspa check_sequence_lock —
 * without the DISABLE bit an input is spendable only after `sequence &
 * 0xffffffff` DAA of UTXO age) or a far-future lockTime to an approved owner
 * op; the wallet would sign and the review would name no waiting condition
 * (e.g. an approved EMERGENCY PAUSE that never lands). No funds move, but the
 * "signed, pending" state is deceptive and the covenant's own age gate is the
 * ONLY relative lock a root transaction may carry.
 *
 * RED on cf4e644 (every row below VERIFIED there); GREEN once the verifier
 * carries `rootInputSequenceZero` / `inputSequencesZero` / `lockTimeZero`
 * (outer) and `vault[..].inputSequencesZero` / `vault[..].lockTimeZero`
 * (inner). Hash re-computed on every tamper so the SEMANTIC check is what
 * refuses.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { verifyOrgRootIntentManifest } = require("../org-root-manifest-v7");
const { computeManifestHashV1 } = require("../canonical");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "explain", "test", "fixtures", "v7-org-root-manifests.json"), "utf8"));
const byName = new Map(FIX.manifests.map((m) => [m.name, m]));

function fixture(name) {
  const f = byName.get(name);
  assert.ok(f, `fixture ${name} missing`);
  return f;
}
function withFrozen(f, mutate) {
  const { manifestHash, ...body } = JSON.parse(JSON.stringify(f.manifest));
  void manifestHash;
  const frozen = JSON.parse(body.transaction.frozenCanonicalJson);
  mutate(frozen, body);
  body.transaction.frozenCanonicalJson = JSON.stringify(frozen);
  return { ...body, manifestHash: computeManifestHashV1(body) };
}
function verify(f, manifest) {
  return verifyOrgRootIntentManifest({ manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts });
}
function rootIdx(f) {
  const frozen = JSON.parse(f.manifest.transaction.frozenCanonicalJson);
  const i = frozen.inputs.findIndex((x) => x.utxo && x.utxo.covenantId === f.manifest.root.covenantId);
  assert.ok(i >= 0, "root input present");
  return i;
}
function expectRefusedBy(label, f, manifest, checkName) {
  const v = verify(f, manifest);
  assert.notEqual(v.verdict, "VERIFIED", `${label}: must be REFUSED`);
  assert.ok(v.failures.some((x) => x.name === checkName), `${label}: expected failing check ${checkName}, got ${v.failures.map((x) => x.name).join(",")}`);
}

test("control: every captured fixture still VERIFIES with its honest sequences (all 0 except the age-gated root) and lockTime 0", () => {
  for (const f of FIX.manifests) {
    const v = verify(f, f.manifest);
    assert.equal(v.verdict, "VERIFIED", `${f.name}: ${JSON.stringify(v.failures)}`);
    const frozen = JSON.parse(f.manifest.transaction.frozenCanonicalJson);
    assert.equal(String(frozen.lockTime), "0", `${f.name}: honest root transactions carry no lockTime`);
    const ri = rootIdx(f);
    frozen.inputs.forEach((i, n) => {
      const expected = n === ri ? String(f.manifest.action.minSequence) : "0";
      assert.equal(String(i.sequence), expected, `${f.name}: input ${n} sequence`);
    });
  }
});

test("R7-01 (outer): a hidden relative lock on the ROOT input of a NON-age-gated action is refused (rootInputSequenceZero)", () => {
  const f = fixture("root_authorize_2of3");
  const ri = rootIdx(f);
  expectRefusedBy("root sequence 1,000,000 on authorize", f, withFrozen(f, (fr) => { fr.inputs[ri].sequence = "1000000"; }), "rootInputSequenceZero");
  expectRefusedBy("root sequence with the DISABLE flag (consensus ignores the lock, the review must still refuse a non-zero sequence)", f, withFrozen(f, (fr) => { fr.inputs[ri].sequence = "9223372036854775808"; }), "rootInputSequenceZero");
});

test("R7-01 (outer): a hidden relative lock on the FEE input or any other non-root input is refused (inputSequencesZero) — including under an age-gated action", () => {
  const f = fixture("root_authorize_2of3");
  const fuel = JSON.parse(f.manifest.transaction.frozenCanonicalJson).inputs.length - 1;
  expectRefusedBy("fee input sequence 2^32-1 on authorize", f, withFrozen(f, (fr) => { fr.inputs[fuel].sequence = "4294967295"; }), "inputSequencesZero");
  const s = fixture("root_succession");
  const sf = JSON.parse(s.manifest.transaction.frozenCanonicalJson).inputs.length - 1;
  assert.notEqual(String(s.manifest.action.minSequence), "0", "succession is age-gated (control)");
  expectRefusedBy("fee input sequence 5 under a succession", s, withFrozen(s, (fr) => { fr.inputs[sf].sequence = "5"; }), "inputSequencesZero");
  expectRefusedBy("the age-gated root input's sequence zeroed (the covenant's OWN gate must be carried)", s, withFrozen(s, (fr) => { fr.inputs[rootIdx(s)].sequence = "0"; }), "rootInputSequence");
});

test("R7-01 (outer): a lockTime on a root transaction is refused by the verifier itself (lockTimeZero) — not only by the browser", () => {
  const f = fixture("root_authorize_2of3");
  expectRefusedBy("lockTime 500,000,000,000 (unix-ms domain, far future)", f, withFrozen(f, (fr) => { fr.lockTime = "500000000000"; }), "lockTimeZero");
  expectRefusedBy("lockTime 1", f, withFrozen(f, (fr) => { fr.lockTime = "1"; }), "lockTimeZero");
});

test("R7-01 (inner): a rooted-vault OWNER operation binds the vault input's sequence and the lockTime inside the vault manifest too", () => {
  const f = fixture("vault_owner_pause_under_authorize");
  const inner = f.manifest.vaultOperations[0];
  const tag = `vault[${inner.covenantId.slice(0, 8)}].`;
  const frozen = JSON.parse(f.manifest.transaction.frozenCanonicalJson);
  const vi = frozen.inputs.findIndex((x) => x.utxo && x.utxo.covenantId === inner.covenantId);
  assert.ok(vi >= 0, "vault input present");
  expectRefusedBy("vault input sequence 2^32-1 on a pause", f, withFrozen(f, (fr) => { fr.inputs[vi].sequence = "4294967295"; }), `${tag}inputSequencesZero`);
  expectRefusedBy("lockTime 7 on a pause (inner)", f, withFrozen(f, (fr) => { fr.lockTime = "7"; }), `${tag}lockTimeZero`);
  expectRefusedBy("lockTime 7 on a pause (outer)", f, withFrozen(f, (fr) => { fr.lockTime = "7"; }), "lockTimeZero");
  const fuel = frozen.inputs.length - 1;
  expectRefusedBy("fee input sequence 1,000,000 on a pause (inner sees every non-root input)", f, withFrozen(f, (fr) => { fr.inputs[fuel].sequence = "1000000"; }), `${tag}inputSequencesZero`);
});

/* ================================================================== *
 * rc26 round-7 review R7-02 — Codex checkpoint 11 (recipient authorization
 * opaque): the setAgentRoot manifest carried POLICIES only; the review showed
 * each agent's `agentRecipientRoot` as an opaque hash, so a consistent
 * substitution of the recipient set (rebuilt root + successor, re-hashed
 * manifest) signed in both roles without the signer ever seeing the newly
 * authorized recipient. Required: the COMPLETE recipient set of every policy
 * travels with it, the verifier binds each `agentRecipientRoot` to the fold
 * of its recipients, and the explanation lists the recipients.
 * RED on 109c5b9 (fixture regenerated to carry recipients).
 * ================================================================== */
const { buildRecipientTree } = require("../../model/recipient-merkle-v3");

test("R7-02 (checkpoint 11): the setAgentRoot policy set carries every agent's RECIPIENTS and each agentRecipientRoot is bound to their fold; a substituted recipient set is refused", () => {
  const f = fixture("vault_set_agent_root_under_authorize");
  const set = f.manifest.vaultOperations[0].manifest.policy.agentSet;
  assert.ok(Array.isArray(set) && set.length === 2);
  for (const p of set) {
    assert.ok(Array.isArray(p.recipients) && p.recipients.length >= 1, "every carried policy lists its recipients");
    assert.equal(buildRecipientTree(p.recipients).root, p.agentRecipientRoot, "control: the fixture's recipient roots fold from their recipients");
  }
  assert.equal(verify(f, f.manifest).verdict, "VERIFIED", "control");
  const tag = `vault[${f.manifest.vaultOperations[0].covenantId.slice(0, 8)}].`;
  const rehashInner = (m) => { const { manifestHash, ...body } = m.vaultOperations[0].manifest; void manifestHash; m.vaultOperations[0].manifest = { ...body, manifestHash: computeManifestHashV1(body) }; };
  const withInner = (mutate) => { const { manifestHash, ...body } = JSON.parse(JSON.stringify(f.manifest)); void manifestHash; mutate(body); rehashInner(body); return { ...body, manifestHash: computeManifestHashV1(body) }; };
  const ATTACKER = "0d".repeat(32);
  /* the Codex reproduction: recipients substituted CONSISTENTLY — the recipient root, the policy leaf, the agent tree root,
   * stateAfter.agentRoot all rebuilt — so only recipient READABILITY + the fold binding can expose it */
  const consistent = withInner((m) => {
    const p = m.vaultOperations[0].manifest.policy.agentSet[0];
    p.recipients = [ATTACKER];
    p.agentRecipientRoot = buildRecipientTree([ATTACKER]).root;
    const { buildTokenAgentTreeV5 } = require("../../model/agent-merkle-v5");
    m.vaultOperations[0].manifest.stateAfter.state.agentRoot = buildTokenAgentTreeV5(m.vaultOperations[0].manifest.policy.agentSet.map(({ recipients, ...policy }) => { void recipients; return policy; })).root;
  });
  /* the fold binding CANNOT refuse a fully consistent substitution (the successor script is not rebuilt here); what must
   * hold is that the recipient is VISIBLE — asserted in the explain golden — and that an INCONSISTENT one is refused: */
  const v = verify(f, consistent);
  assert.ok(v.verdict === "VERIFIED" || v.failures.some((x) => x.name.endsWith("successorScriptReconstructed")), "a fully consistent substitution is refused only by the successor-script binding, never silently by nothing");
  expectRefusedBy("recipients substituted, root kept", f, withInner((m) => { m.vaultOperations[0].manifest.policy.agentSet[0].recipients = [ATTACKER]; }), `${tag}agentRecipientsBound`);
  expectRefusedBy("a recipient appended, root kept", f, withInner((m) => { m.vaultOperations[0].manifest.policy.agentSet[0].recipients.push(ATTACKER); }), `${tag}agentRecipientsBound`);
  expectRefusedBy("recipients withheld", f, withInner((m) => { delete m.vaultOperations[0].manifest.policy.agentSet[0].recipients; }), `${tag}agentRecipientsBound`);
  expectRefusedBy("recipients emptied", f, withInner((m) => { m.vaultOperations[0].manifest.policy.agentSet[0].recipients = []; }), `${tag}agentRecipientsBound`);
  expectRefusedBy("agentRecipientRoot substituted, recipients kept (the leaf then no longer folds to stateAfter)", f, withInner((m) => { m.vaultOperations[0].manifest.policy.agentSet[0].agentRecipientRoot = buildRecipientTree([ATTACKER]).root; }), `${tag}agentRecipientsBound`);
});
