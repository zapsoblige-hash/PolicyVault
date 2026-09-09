"use strict";

/*
 * BROWSER — the guided ORGANIZATIONAL ROOT setup + humanized root / request
 * surfaces of web/org-root-ui.js (owner UX directive 2026-09-05), over the
 * REAL committed web/core-bundle.js and the shared setup components.
 *
 * Pins: no DAA / M-K-R / comma-delimited entry in routine fields; the
 * governance copy states what the frozen v0.7-root covenant actually does
 * (a freeze stops governance actions, NOT agent payments; recovery and
 * succession are gated by the root output's relative age and land frozen;
 * the funding is never withdrawable); the exact review is CROSS-CHECKED
 * against the server's genesis summary and refuses on any mismatch; the
 * viewer's role and the waiting-period estimates are shown truthfully.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const core = require("../core-bundle.js");
const orgRootUiMod = require("../org-root-ui.js");
const setupMod = require("../setup-ui.js");
const FIXTURES = JSON.parse(require("fs").readFileSync(require("path").join(__dirname, "..", "..", "core", "explain", "test", "fixtures", "v7-org-root-manifests.json"), "utf8"));
const { safeJsonFromManifest } = require("./org-root-ui.test.js");
const manifestOf = (name) => FIXTURES.manifests.find((x) => x.name === name).manifest;
/* a genesis wallet payload consistent with a genesis summary: the funder's
 * P2PK inputs, output 0 = the P2SH root output carrying rootValueKas, output
 * 1 = change back to the funder; fee = requiredFeeSompi */
/* the root output's P2SH is the EXACT script the reviewed rules compile to
 * (shared-core reconstruction of the frozen v0.7 root, Codex checkpoint 3) */
function rootSpkFor(summary, norm) {
  const t = summary.template;
  return "0000" + core.rootScriptV7.genesisRootSpkHexV7({
    template: { orgId: summary.orgId, recoveryDelayDaa: String(t.recoveryDelayDaa), successorPk: String(t.successorPk), successionDelayDaa: String(t.successionDelayDaa), rootMaxFeePerTx: String(t.rootMaxFeePerTx) },
    ownerSet: { owners: [...norm.ownerSet.owners], ownerM: norm.ownerSet.ownerM.toString(), emergencyK: norm.ownerSet.emergencyK.toString(), recoveryM: norm.ownerSet.recoveryM.toString() }
  });
}
function genesisPayloadFor(summary, funderXOnly, norm, tamper) {
  const rootValue = core.amounts.kasToSompi(summary.rootValueKas);
  const fee = BigInt(summary.requiredFeeSompi);
  const inputAmount = rootValue + fee + 50000000n;
  const safe = {
    id: summary.txId, version: 1,
    inputs: [{ transactionId: "5e".repeat(32), index: 0, sequence: "0", sigOpCount: 0, computeBudget: 10, signatureScript: "", utxo: { address: null, amount: inputAmount.toString(), scriptPublicKey: `000020${funderXOnly}ac`, blockDaaScore: "0", isCoinbase: false, covenantId: null } }],
    outputs: [{ value: rootValue.toString(), scriptPublicKey: rootSpkFor(summary, norm), covenant: { authorizingInput: 0, covenantId: summary.covenantId } }, { value: "50000000", scriptPublicKey: `000020${funderXOnly}ac`, covenant: null }],
    subnetworkId: "00".repeat(20), lockTime: "0", gas: "0", storageMass: "0", payload: ""
  };
  if (tamper) tamper(safe);
  return JSON.stringify(safe);
}

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const OWNERS = { "kaspatest:qown1": K(0x71), "kaspatest:qown2": K(0x72), "kaspatest:qown3": K(0x73), "kaspatest:qfunder": K(0xf1), "kaspatest:qsucc": K(0xa1) };
function fakeApi() {
  const calls = [];
  return {
    calls,
    async getJSON(p) { calls.push({ method: "GET", path: p }); throw new Error("unmapped"); },
    async postJSON(p, body) { calls.push({ method: "POST", path: p, body }); throw new Error("unmapped"); },
    async resolveXOnly(a) { if (Object.prototype.hasOwnProperty.call(OWNERS, a)) return OWNERS[a]; throw Object.assign(new Error(`address rejected: ${a}`), { code: "ADDRESS_INVALID" }); }
  };
}
function mod() {
  const api = fakeApi();
  const setup = setupMod.createModule({ core });
  return { api, setup, m: orgRootUiMod.createModule({ api, core, setup }) };
}
function draft(overrides = {}) {
  return {
    label: "Acme", owners: [{ address: "kaspatest:qown1", label: "Alice" }, { address: "kaspatest:qown2", label: "Bob" }, { address: "kaspatest:qown3", label: "Carol" }],
    ownerM: "2", emergencyK: "1", recoveryEnabled: true, recoveryM: "1", recoveryDelay: { preset: "30d" },
    successionEnabled: false, successorAddress: "", successionDelay: { preset: "90d" },
    rootValueKas: "1", rootMaxFeePerTxKas: "0.001", signerAddress: "kaspatest:qfunder", ...overrides
  };
}
const rootRecord = (over = {}) => ({
  rootCovenantId: "r".repeat(64), orgId: "o".repeat(64), label: "Acme",
  state: { ownerM: "2", emergencyK: "1", recoveryM: "1", frozen: 0, rootNonce: "3" },
  template: { recoveryDelayDaa: "25920000", successionDelayDaa: "77760000", successorPk: "00".repeat(32), rootMaxFeePerTx: "100000" },
  slots: [{ slot: 1, publicKey: K(0x71), address: "kaspatest:qown1", label: "Alice" }, { slot: 2, publicKey: K(0x72), address: "kaspatest:qown2", label: "Bob" }, { slot: 3, publicKey: K(0x73), address: "kaspatest:qown3", label: "Carol" }],
  generation: 3, pendingRequestId: null, live: { outpoint: { transactionId: "t".repeat(64), index: 0 }, blockDaaScore: "1000000" }, ...over
});

/* ---------------- setup rendering ---------------- */
test("renderGenesisSetupHtml: five steps, only the current panel visible, no DAA / M-K-R / comma-delimited routine fields", () => {
  const { m } = mod();
  const html = m.renderGenesisSetupHtml({ draft: draft(), step: 1, errors: new Map(), connectedAddress: "kaspatest:qfunder", network: "testnet-10" });
  for (const id of ["owners", "approvals", "emergency", "funding", "review"]) assert.match(html, new RegExp(`data-setup-step="${id}"`));
  assert.match(html, /data-setup-step="owners" hidden/);
  assert.match(html, /data-setup-step="approvals">/);
  assert.match(html, /data-step="approvals" aria-current="step"/);
  assert.ok(!/one per line|64-hex public key\[, label\]|\(M\)|\(K\)|\(R, 0 = disabled\)|delay \(DAA score\)/.test(html), "no legacy encoding-facing labels");
  assert.match(html, /<option value="2" selected>2 of 3 owners<\/option>/);
  assert.match(html, /name="ownerLabel"[^>]*value="Alice"/);
  assert.match(html, /Owners needed to approve changes/);
  assert.match(html, /Owners needed for an emergency freeze/);
  assert.match(html, /Owners needed to recover control/);
  assert.match(html, /Recovery waiting period/);
  assert.match(html, /Successor waiting period/);
  assert.match(html, /Governance funding/);
  assert.match(html, /Wallet funding this setup/);
  assert.match(html, /data-setup-build="1">Build governance root &amp; review</);
  assert.match(html, /data-use-connected="owner"/);
});

test("governance copy states exactly what the frozen covenant does (freeze / recovery / succession / funding)", () => {
  const { m } = mod();
  const C = m.ROOT_COPY;
  const freeze = C.FREEZE(1, 2, 3);
  assert.match(freeze, /does NOT stop agent payments/);
  assert.match(freeze, /at most ONE vault in the same transaction/);
  assert.match(freeze, /2 of 3 owners must unfreeze and then pause each vault/);
  assert.match(freeze, /cannot spend, change owners, or unfreeze/);
  assert.match(freeze, /accepts only a change of owners or rules, an unfreeze, recovery and succession/);
  const rec = C.RECOVERY(1, 3, "about 30 days");
  assert.match(rec, /no governance transaction touches this root for about 30 days/);
  assert.match(rec, /Any governance transaction restarts the wait/);
  assert.match(rec, /lands the root FROZEN/);
  // UX-08 (Codex checkpoint 2): recovery off does NOT imply that an enabled
  // succession is unavailable — the copy depends on the succession state
  assert.match(C.RECOVERY_OFF(false), /no one can regain control/);
  assert.match(C.RECOVERY_OFF(true), /only the designated successor can regain control, after its waiting period/);
  assert.doesNotMatch(C.RECOVERY_OFF(true), /no one can regain control/);
  // rc15 review F-05: budgets RESET every period — the drain continues until the
  // fee reserve or the deposit is exhausted; the remainder stays locked
  assert.match(C.RECOVERY_OFF(false), /until the fee reserve or the deposit is exhausted \(budgets reset every period\)/);
  assert.doesNotMatch(C.RECOVERY_OFF(false), /budgets or fee reserves run out/);
  // UX-08: succession may retain previous keys; unfreezing uses the INSTALLED set's quorum
  assert.match(C.SUCCESSION("about 90 days"), /a previous owner keeps authority only if the successor lists that key again/);
  assert.match(C.SUCCESSION("about 90 days"), /unfreeze with their own approval quorum \(M of N of the new set\)/);
  assert.doesNotMatch(C.SUCCESSION("about 90 days"), /previous owners lose every authority|replaces ALL owners|full quorum/);
  // rc15 review F-07: R may EQUAL M; a ROTATE is also allowed while frozen
  assert.match(C.RECOVERY(1, 3, "about 30 days"), /before normal governance resumes/);
  assert.doesNotMatch(C.RECOVERY(1, 3, "about 30 days"), /before anything else/);
  assert.match(C.SUCCESSION("about 90 days"), /installs the set of owners the successor chooses/); // UX-08: no longer "replaces ALL owners"
  assert.match(C.SUCCESSION("about 90 days"), /permanent/);
  assert.match(C.WAIT_RESET, /not from a login, a payment, or a calendar date/);
  assert.match(C.FUNDING, /can never be withdrawn/);
  assert.match(C.FUNDING, /paid for by the wallet that starts them/);
  assert.match(C.FUNDER, /grants no ownership/);
  assert.match(C.HOSTED_VS_ROOT, /grants nobody owner authority/);
  assert.ok(!/organization-wide halt|stops all payments/i.test(freeze));
  const html = m.renderGenesisSetupHtml({ draft: draft({ recoveryEnabled: false }), step: 2, errors: new Map(), connectedAddress: "kaspatest:qfunder" });
  assert.match(html, /Recovery is off\. If too many owner keys are lost, no one can regain control/);
  assert.match(html, /data-recovery-fields="1" hidden/);
  assert.match(html, /data-succession-fields="1" hidden/);
});

/* ---------------- validation ---------------- */
test("validateGenesisDraft: full validation runs the core's well-formedness rule and maps refusals onto fields", async () => {
  const { m } = mod();
  const ok = await m.validateGenesisDraft(draft(), { connectedAddress: "kaspatest:qfunder" });
  assert.equal(ok.ok, true, [...ok.errors].map(String).join(";"));
  assert.equal(ok.norm.ownerSet.ownerM, 2n);
  assert.equal(ok.norm.ownerSet.recoveryM, 1n);
  assert.equal(ok.norm.recoveryDelayDaa, 25920000);
  assert.equal(ok.form.recoveryDelayDaa, "25920000");
  const k = await m.validateGenesisDraft(draft({ ownerM: "1", emergencyK: "2" }), { connectedAddress: "kaspatest:qfunder" });
  assert.equal(k.ok, false);
  assert.match(k.errors.get("emergencyK"), /cannot exceed/);
  const step = await m.validateGenesisDraft(draft({ owners: [{ address: "kaspatest:qown1" }, { address: "kaspatest:qown1" }] }), { step: "owners" });
  assert.equal(step.ok, false);
  assert.match(step.errors.get("ownerRows")[1], /Same wallet as owner 1/);
});

/* ---------------- exact review + cross-check ---------------- */
function serverSummaryFor(norm, over = {}) {
  const slots = core.ownerSetV7.activeOwnerSlotsV7(norm.ownerSet).map((s) => ({ slot: s.slot, publicKey: s.publicKey, address: `kaspatest:qown${s.slot}`, label: "" }));
  return {
    kind: "genesis-summary", contractVersion: "policyvault-0.7-root", networkId: "testnet-10", orgId: "0a".repeat(32), covenantId: "0c".repeat(32),
    template: { orgId: "0a".repeat(32), recoveryDelayDaa: String(norm.recoveryDelayDaa), successorPk: norm.successorPk, successionEnabled: norm.successorPk !== "00".repeat(32), successionDelayDaa: String(norm.successionDelayDaa), rootMaxFeePerTx: norm.rootMaxFeePerTxSompi.toString() },
    slots, initialState: { ownerM: norm.ownerSet.ownerM.toString(), emergencyK: norm.ownerSet.emergencyK.toString(), recoveryM: norm.ownerSet.recoveryM.toString(), frozen: "0", rootNonce: "0" },
    rootValueKas: core.amounts.sompiToKas(norm.rootValueSompi), txId: "t".repeat(64), requiredFeeSompi: "208300", ...over
  };
}

test("genesisCrossCheck: the server summary is compared field by field with the reviewed rules; any divergence refuses", async () => {
  const { m } = mod();
  const v = await m.validateGenesisDraft(draft(), { connectedAddress: "kaspatest:qfunder" });
  const norm = v.norm;
  assert.deepEqual(m.genesisCrossCheck({ summary: serverSummaryFor(norm), norm }), { ok: true, mismatches: [] });
  const tM = m.genesisCrossCheck({ summary: serverSummaryFor(norm, { initialState: { ownerM: "1", emergencyK: "1", recoveryM: "1" } }), norm });
  assert.equal(tM.ok, false);
  assert.match(tM.mismatches.join(";"), /owners needed to approve changes: server 1, reviewed 2/);
  const s = serverSummaryFor(norm);
  s.slots[1] = { ...s.slots[1], publicKey: K(0x99) };
  const tKey = m.genesisCrossCheck({ summary: s, norm });
  assert.match(tKey.mismatches.join(";"), /owner 2 key differs/);
  const tDelay = m.genesisCrossCheck({ summary: serverSummaryFor(norm, { template: { ...serverSummaryFor(norm).template, recoveryDelayDaa: "25919999" } }), norm });
  assert.match(tDelay.mismatches.join(";"), /recovery waiting period \(DAA\): server 25919999, reviewed 25920000/);
  const tValue = m.genesisCrossCheck({ summary: serverSummaryFor(norm, { rootValueKas: "2" }), norm });
  assert.match(tValue.mismatches.join(";"), /governance funding/);
  assert.equal(m.genesisCrossCheck({ summary: { kind: "other" }, norm }).ok, false);
});

test("renderGenesisReviewHtml: CHECKED review with human sections + exact fee breakdown, DO NOT SIGN on mismatch, technical panel kept", async () => {
  const { m } = mod();
  const { norm } = await m.validateGenesisDraft(draft(), { connectedAddress: "kaspatest:qfunder" });
  const summary = serverSummaryFor(norm);
  const ok = m.renderGenesisReviewHtml({ norm, summary, crossCheck: m.genesisCrossCheck({ summary, norm }), connectedAddress: "kaspatest:qfunder" });
  assert.match(ok, /CHECKED — PolicyVault's description of the built transaction matches the rules you reviewed/);
  assert.match(ok, /Changes need[^]*2 of 3 owners/);
  assert.match(ok, /1 of 3 owners after the root is untouched for about 30 days/);
  assert.match(ok, /Recovery waiting period[^]*about 30 days<details class="adv f-tech"><summary>Technical detail<\/summary>exactly 25920000 DAA score/);
  assert.match(ok, /Designated successor[^]*none \(permanent\)/);
  assert.match(ok, /Network fee for creating the root[^]*0\.002083 KAS/);
  assert.match(ok, /Total leaving your wallet[^]*1\.002083 KAS/);
  assert.match(ok, /EXACT ROOT POLICY BEFORE SIGNING/);
  assert.match(ok, /Recovery delay: 25920000 DAA score/);
  for (const k of [K(0x71), K(0x72), K(0x73)]) assert.ok(ok.includes(k), "full keys untruncated in the technical panel");
  const bad = m.renderGenesisReviewHtml({ norm, summary, crossCheck: { ok: false, mismatches: ["owner 2 key differs from the reviewed owner"] }, connectedAddress: "x" });
  assert.match(bad, /DO NOT SIGN — the built transaction does not match/);
  assert.match(bad, /owner 2 key differs/);
});

/* ---------------- root detail / request detail ---------------- */
test("renderRootDetailHtml: plain-language governance, the viewer's role, waiting-period estimates, state-aware actions", () => {
  const { m } = mod();
  const owner = m.renderRootDetailHtml(rootRecord(), { viewerXOnly: K(0x72), currentDaa: "1500000" });
  assert.match(owner, /ON_CHAIN_ORGANIZATIONAL_ROOT/);
  assert.match(owner, /You hold owner slot 2 \(Bob\)/);
  assert.match(owner, /Changes need[^]*2 of 3 owners/);
  assert.match(owner, /Emergency freeze[^]*1 of 3 owners — stops governance actions; agent payments continue/);
  assert.match(owner, /1 of 3 owners after the root is untouched for about 30 days<\/div>/, "approximate in the row; exact DAA under Technical details");
  assert.match(owner, /recovery delay 25920000 DAA/);
  assert.match(owner, /Recovery of control: about 29 days 10 hours still to wait \(root untouched for about 13 hours 53 minutes/);
  assert.match(owner, /data-rootaction="authorize"[^>]*>Authorize \(heartbeat\)</);
  assert.match(owner, /data-rootaction="rotate"[^>]*>Change owners or rules</);
  assert.match(owner, /data-rootaction="freeze"[^>]*>Emergency freeze</);
  assert.match(owner, /data-rootaction="ownerRecover"[^>]*>Recover control</);
  assert.ok(!/single[- ]owner/i.test(owner));
  assert.match(owner, /<button disabled class="warn" data-rootaction="succession"/, "no successor -> succession disabled");
  assert.match(owner, /<button disabled class="warn" data-rootaction="unfreeze"/, "not frozen -> unfreeze disabled");
  const frozen = m.renderRootDetailHtml(rootRecord({ state: { ownerM: "2", emergencyK: "1", recoveryM: "0", frozen: 1, rootNonce: "4" } }), { viewerXOnly: K(0x71) });
  assert.match(frozen, /FROZEN — no governance action can be approved for any vault of this organization until 2 of 3 owners unfreeze\. Agent payments continue/);
  assert.match(frozen, /<button disabled class="" data-rootaction="authorize"/);
  assert.match(frozen, /<button disabled class="warn" data-rootaction="ownerRecover"/, "recovery off -> disabled");
  assert.match(frozen, /off — if too many keys are lost, control cannot be regained/);
  const stranger = m.renderRootDetailHtml(rootRecord(), { viewerXOnly: K(0x99) });
  assert.match(stranger, /not an owner of this root — read-only/);
  assert.match(stranger, /<button disabled class="" data-rootaction="authorize"/);
  for (const t of [...owner.matchAll(/<table[^>]*>/g)]) assert.match(t[0], /class="mtable"/);
});

test("renderRequestDetailHtml: approvals collected/required, the connected wallet's role, the next possible action, withdraw offered while unsigned", () => {
  const { m } = mod();
  const req = { id: "q1", kind: "rootAction", action: "rotate", actionClass: "AUTHORITY-EXPANDING", state: "AUTHORIZED", signaturesPresent: 1, requiredApprovals: "2", manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspatest:qown1", status: "SIGNED" }, { slot: 2, publicKey: K(0x72), address: "kaspatest:qown2", status: "PENDING" }, { slot: 3, publicKey: K(0x73), address: "kaspatest:qown3", status: "PENDING" }], warnings: ["DANGEROUS_ROTATION"] };
  const html = m.renderRequestDetailHtml(req, { orgRoot: rootRecord(), viewerXOnly: K(0x72) });
  assert.match(html, /Change owners or rules/);
  assert.match(html, /1 of 2 collected/);
  assert.match(html, /You hold owner slot 2: your approval is needed/);
  assert.match(html, /Collect 1 more owner approval, then finalize/);
  /* STALE ASSUMPTION corrected (F-6, owner-approved backend semantics, 2026-09-08): a request that already carries an
   * owner signature is NEVER withdrawn (sdk rejectOrgRootRequest refuses it with CANNOT_REJECT) — offering the control
   * here consumed a click on a pre-detectable refusal. The detail now states the reservation and the authorized next
   * step instead; withdrawal is offered only for an UNSIGNED, never-attempted request. */
  assert.doesNotMatch(html, /data-rootreject="q1"/, "a request carrying a slot signature is not offered withdrawal (F-6)");
  assert.match(html, /data-reservation-next="collect"/);
  assert.match(html, /a request carrying a signature is not withdrawn; collect the remaining approvals/);
  assert.match(html, /dismissing a wallet prompt, closing this window or disconnecting the wallet does not release it/);
  const unsigned = m.renderRequestDetailHtml({ ...req, signaturesPresent: 0, slots: req.slots.map((x) => ({ ...x, status: "PENDING" })) }, { orgRoot: rootRecord(), viewerXOnly: K(0x72) });
  assert.match(unsigned, /data-rootreject="q1"/, "an unsigned, never-attempted request IS offered the safe withdrawal");
  assert.match(unsigned, /data-reservation-next="withdraw"/);
  assert.match(html, /<button disabled data-rootfinalize="q1"/);
  assert.match(html, /role="status"/);
  // STALE FIXTURE corrected (UX-09): a server count of 2 must be backed by two SIGNED slots, else the detail fails closed
  // Codex checkpoint 6 (UX-03): the wallet offered Finalize is the OWNER OF THE FEE INPUT read from the frozen transaction (owner 1 funds it here)
  const feeTx = JSON.stringify({ inputs: [{ utxo: { scriptPublicKey: `0000aa20${"0a".repeat(32)}87` } }, { utxo: { scriptPublicKey: `000020${K(0x71)}ac` } }] });
  const atQuorum = { ...req, action: "ownerRecover", signaturesPresent: 2, rootInputIndex: 0, transaction: { unsignedSafeJson: feeTx, signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }] }, slots: req.slots.map((x, i) => (i < 2 ? { ...x, status: "SIGNED" } : x)) };
  const rec = m.renderRequestDetailHtml(atQuorum, { orgRoot: rootRecord(), viewerXOnly: K(0x71), currentDaa: "1500000" });
  assert.match(rec, /Waiting condition[^]*still to wait/);
  assert.match(rec, /Enough approvals: Finalize/);
  assert.match(rec, /<button data-rootfinalize="q1"/);
  const notPayer = m.renderRequestDetailHtml(atQuorum, { orgRoot: rootRecord(), viewerXOnly: K(0x72), currentDaa: "1500000" });
  assert.match(notPayer, /<button disabled data-rootfinalize="q1"/);
  assert.match(notPayer, /kaspatest:qown1 \(owner slot 1\) finalizes it/, "the fee payer is named by its owner slot + address");
  const noTx = m.renderRequestDetailHtml({ ...atQuorum, transaction: undefined }, { orgRoot: rootRecord(), viewerXOnly: K(0x71), currentDaa: "1500000" });
  assert.match(noTx, /<button disabled data-rootfinalize="q1"/, "no frozen transaction => no verifiable fee input => finalize disabled (fail closed)");
  const done = m.renderRequestDetailHtml({ ...req, state: "CHAIN_VERIFIED", signaturesPresent: 2 }, {});
  assert.match(done, /Chain-verified/);
  assert.ok(!/data-rootreject/.test(done));
});

test("renderDangerousConfirmHtml: plain consequence + approximate waiting period, the fixed warning texts kept verbatim", () => {
  const { m } = mod();
  const html = m.renderDangerousConfirmHtml({ action: "ownerRecover", rootLabel: "Acme", delayDaa: "25920000", orgRoot: rootRecord() });
  assert.match(html, /Recover control installs a NEW set of owners on the 1 of 3 quorum after the root has been untouched for about 30 days/);
  assert.match(html, /It does not move any funds; it changes who governs/);
  assert.match(html, /lands the root FROZEN/);
  assert.match(html, /RELATIVE input age/);
  assert.match(html, /heartbeat AUTHORIZE/);
  assert.match(html, /25920000 DAA score \(about 30 days\)/);
  assert.match(html, /CONFIRM OWNERRECOVER/);
  const unf = m.renderDangerousConfirmHtml({ action: "unfreeze", rootLabel: "Acme", orgRoot: rootRecord() });
  assert.match(unf, /It needs 2 of 3 owners/);
});

test("actionLabel / describeDelay / new-owner-set helpers", async () => {
  const { m } = mod();
  assert.equal(m.actionLabel("rotate"), "Change owners or rules");
  assert.equal(m.actionLabel("ownerRecover"), "Recover control");
  assert.equal(m.actionLabel("__proto__"), "__proto__", "unknown actions echo, never a default label");
  assert.equal(m.describeDelay("864000"), "about 1 day (exactly 864000 DAA score)");
  const d = m.newOwnerSetDraftFrom(rootRecord(), { action: "rotate", connectedAddress: "kaspatest:qown1" });
  assert.equal(d.owners.length, 3);
  assert.deepEqual([d.ownerM, d.emergencyK, d.recoveryEnabled, d.recoveryM], ["2", "1", true, "1"]);
  const html = m.renderNewOwnerSetHtml({ action: "rotate", orgRoot: rootRecord(), draft: d, errors: new Map(), connectedAddress: "kaspatest:qown1" });
  assert.match(html, /<option value="2" selected>2 of 3 owners<\/option>/);
  assert.match(html, /Owners: 3 now → 3 after this change/);
  const bad = await m.validateNewOwnerSetDraft({ ...d, ownerM: "1", emergencyK: "2" }, { action: "rotate", orgRoot: rootRecord() });
  assert.equal(bad.ok, false);
  assert.match(bad.errors.get("emergencyK"), /cannot exceed/);
  const ok = await m.validateNewOwnerSetDraft(d, { action: "rotate", orgRoot: rootRecord() });
  assert.equal(ok.ok, true, [...ok.errors].map(String).join(";"));
  assert.deepEqual(ok.ownerRows.map((o) => o.slot), [1, 2, 3]);
  // rc18 review R3-02: the posted params carry EXACTLY the SDK builder's shape (12 dense x-only slots + M/K/R as digit strings)
  assert.deepEqual(Object.keys(ok.params), ["newOwnerSet"]);
  assert.equal(ok.params.newOwnerSet.owners.length, 12);
  assert.deepEqual(ok.params.newOwnerSet.owners.slice(0, 3), [K(0x71), K(0x72), K(0x73)]);
  assert.ok(ok.params.newOwnerSet.owners.slice(3).every((o) => o === "00".repeat(32)));
  assert.deepEqual([ok.params.newOwnerSet.ownerM, ok.params.newOwnerSet.emergencyK, ok.params.newOwnerSet.recoveryM], ["2", "1", "1"]);
  const succ = await m.validateNewOwnerSetDraft({ ...d, successorAddress: "kaspatest:qsucc" }, { action: "succession", orgRoot: rootRecord() });
  assert.equal(succ.ok, false);
  assert.match(succ.errors.get("owners"), /Owner 1 must change in a succession/);
});

test("createGenesisRequest posts the delays as CANONICAL DIGIT STRINGS (the server's canonicalAmountParam refuses JS numbers)", async () => {
  const { api, m } = mod();
  api.postJSON = async (p, body) => { api.calls.push({ method: "POST", path: p, body }); return { request: { id: "req1", rootCovenantId: "r".repeat(64), kind: "rootGenesis" } }; };
  const v = await m.validateGenesisDraft(draft({ recoveryDelay: { preset: "custom", customValue: "45", customUnit: "day" } }), { connectedAddress: "kaspatest:qfunder" });
  assert.equal(v.ok, true);
  await m.createGenesisRequest(v.form);
  const body = api.calls.find((c) => c.path === "/org-roots").body;
  assert.equal(body.recoveryDelayDaa, "38880000");
  assert.equal(body.successionDelayDaa, "77760000");
  assert.equal(typeof body.recoveryDelayDaa, "string");
  assert.match(body.recoveryDelayDaa, /^(0|[1-9][0-9]*)$/);
  assert.equal(body.signerAddress, "kaspatest:qfunder");
  assert.equal(body.successorAddress, null);
  assert.equal(String(body.recoveryM), "1");
});

test("signGenesisRequest signs the API-PRESENTED frozen transaction (request.transaction; `build` is stripped by the server) and posts to the single-signer route — bound to the review and the exact payload (UX-02)", async () => {
  const { api, m } = mod();
  const posted = [];
  api.postJSON = async (p, body) => { posted.push({ p, body }); return { request: { id: "g1", state: "SIGNED" } }; };
  const { norm } = await m.validateGenesisDraft(draft(), { connectedAddress: "kaspatest:qfunder" });
  const summary = serverSummaryFor(norm, { txId: "7e".repeat(32) });
  const FUNDER = OWNERS["kaspatest:qfunder"];
  const unsignedSafeJson = genesisPayloadFor(summary, FUNDER, norm);
  const request = { id: "g1", kind: "rootGenesis", rootCovenantId: "r".repeat(64), manifest: summary, transaction: { unsignedSafeJson, signInputs: [{ index: 0, sighashType: 1 }] } };
  let seen = null;
  const adapter = { signInputs: async (u, list, opts) => { seen = { u, list, opts }; return "{\"signed\":true}"; } };
  const crossCheck = m.genesisCrossCheck({ summary, norm });
  const res = await m.signGenesisRequest({ request, adapter, network: "testnet-10", expectedSignerAddress: "kaspatest:qfunder", connectedXOnly: FUNDER, crossCheck, norm });
  assert.equal(seen.u, unsignedSafeJson, "the payload verified is the payload signed");
  assert.deepEqual(seen.list, [{ index: 0, sighashType: 1 }]);
  assert.equal(posted[0].p, `/org-roots/${"r".repeat(64)}/requests/g1/signature`);
  assert.equal(posted[0].body.signedSafeJson, "{\"signed\":true}");
  assert.equal(res.request.state, "SIGNED");
  // `build` fallback for in-process callers holding the raw record
  const viaBuild = { ...request, transaction: undefined, build: { unsignedSafeJson, signInputs: [{ index: 0, sighashType: 1 }] } };
  await m.signGenesisRequest({ request: viaBuild, adapter, network: "testnet-10", expectedSignerAddress: "kaspatest:qfunder", connectedXOnly: FUNDER, crossCheck, norm });
  let invoked = false;
  await assert.rejects(() => m.signGenesisRequest({ request: { id: "x", rootCovenantId: "r".repeat(64) }, adapter: { signInputs: async () => { invoked = true; return "{}"; } }, network: "testnet-10", expectedSignerAddress: "a", connectedXOnly: FUNDER, crossCheck, norm }), (e) => e.code === "REQUEST_NOT_SIGNABLE");
  assert.equal(invoked, false);
});

test("fetchSlotRequest unwraps the server's { slotRequest } body into the bare envelope signOwnSlot consumes, and refuses a body with no envelope", async () => {
  const { api, m } = mod();
  const envelope = { requestVersion: "x", slot: { number: 1, index: 0, publicKey: K(0x71) }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: 0, sighashType: 1 }] }, unsignedSafeJson: "{}" };
  api.getJSON = async (p) => (p.endsWith("/slot-request/1") ? { slotRequest: envelope } : p.endsWith("/slot-request/2") ? envelope : { unrelated: true });
  assert.deepEqual(await m.fetchSlotRequest("r", "q", 1), envelope);
  assert.deepEqual(await m.fetchSlotRequest("r", "q", 2), envelope, "a bare envelope still passes");
  await assert.rejects(() => m.fetchSlotRequest("r", "q", 3), (e) => e.code === "RESPONSE_BINDING_MISMATCH");
});

test("finalizeRequest: the STARTING owner's wallet signs the LAST (fuel) input and the 66-byte script is posted; other owners are refused before the wallet; malformed scripts refused", async () => {
  const { api, m } = mod();
  const posted = [];
  api.postJSON = async (p, body) => { posted.push({ p, body }); return { request: { id: "q1", state: "SIGNED" } }; };
  const sig = "41" + "ab".repeat(64) + "01";
  const manifest = manifestOf("root_authorize_2of3"); // 2 inputs: root (0) + the starting owner's fuel (1, key 64..64)
  const FUEL_OWNER = "64".repeat(32);
  const request = { id: "q1", kind: "rootAction", action: "authorize", state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: "2", createdBy: "kaspatest:qown1", rootInputIndex: 0, manifest, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspatest:qown1", status: "SIGNED" }, { slot: 2, publicKey: K(0x72), address: "kaspatest:qown2", status: "SIGNED" }, { slot: 3, publicKey: K(0x73), address: "kaspatest:qown3", status: "PENDING" }], transaction: { unsignedSafeJson: safeJsonFromManifest(manifest), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }] } };
  let seen = null;
  const adapter = { signInputs: async (u, list, opts) => { seen = { u, list, opts }; return JSON.stringify({ inputs: [{ signatureScript: "" }, { signatureScript: sig }] }); } };
  const res = await m.finalizeRequest("r", "q1", request, { adapter, network: "testnet-10", expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
  assert.deepEqual(seen.list, [{ index: 1, sighashType: 1 }], "only the fuel (last) input is signed at finalize");
  assert.equal(seen.u, request.transaction.unsignedSafeJson, "the payload verified is the payload signed");
  assert.equal(posted[0].body.fuelSignatureScriptHex, sig);
  assert.equal(res.request.state, "SIGNED");
  assert.equal(m.fuelInputIndex(request), 1);
  assert.equal(m.fuelOwnerGate(request, "kaspatest:qown2").ok, false);
  let invoked = false;
  // Codex checkpoint 6 (UX-03): finalization authority is the FEE INPUT's owner key, never `createdBy` — a wallet that does not own the
  // fee input (owner 2 here) is refused before the wallet even though it is an approving owner
  await assert.rejects(() => m.finalizeRequest("r", "q1", request, { adapter: { signInputs: async () => { invoked = true; return "{}"; } }, network: "testnet-10", expectedSignerAddress: "kaspatest:qown2", connectedXOnly: K(0x72) }), (e) => e.code === "NOT_THE_SIGNER");
  assert.equal(invoked, false, "a wallet that does not own the fee input never reaches the wallet");
  assert.equal(m.fuelOwnerGate(request, K(0x72)).ok, false);
  assert.equal(m.fuelOwnerGate(request, FUEL_OWNER).ok, true, "the fee input's owner finalizes even though it did not start the request");
  assert.equal(m.feePayerOf(request).xonly, FUEL_OWNER);
  await assert.rejects(() => m.finalizeRequest("r", "q1", request, { adapter: { signInputs: async () => JSON.stringify({ inputs: [{}, { signatureScript: "abcd" }] }) }, network: "testnet-10", expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), (e) => e.code === "INVALID_SIGNATURE_RESPONSE");
  // in-process callers may pass the fuel script directly (no wallet)
  const direct = await m.finalizeRequest("r", "q1", request, { fuelSignatureScriptHex: sig });
  assert.equal(direct.request.state, "SIGNED");
  // rc18 review R3-11: the detail text for the non-starting owner and for the starter (restored)
  const html = m.renderRequestDetailHtml(request, { viewerAddress: "kaspatest:qown2", viewerXOnly: K(0x72) });
  assert.match(html, /<button disabled data-rootfinalize="q1"/);
  assert.match(html, /the wallet holding key 6464[0-9a-f]+ \(not an owner slot\) finalizes it/, "the fee payer (the fee input's owner) is named, not the starter");
  assert.match(html, /the request was started by kaspatest:qown1/, "the starter stays visible as metadata");
  const starter = m.renderRequestDetailHtml(request, { viewerAddress: "kaspatest:qown1", viewerXOnly: K(0x71) });
  assert.match(starter, /<button disabled data-rootfinalize="q1"/, "the STARTER cannot finalize when another wallet funds the fee (Codex checkpoint 6, UX-03)");
  const mine = m.renderRequestDetailHtml(request, { viewerAddress: "kaspatest:qfuel", viewerXOnly: FUEL_OWNER });
  assert.match(mine, /<button data-rootfinalize="q1"/);
  assert.match(mine, /your wallet funds the network fee and signs the fee input/);
});

test("the new renderers refuse without the setup components (never a half-rendered form), while the legacy surface still works", () => {
  const api = fakeApi();
  const legacy = orgRootUiMod.createModule({ api, core });
  assert.throws(() => legacy.renderGenesisSetupHtml({ draft: draft(), step: 0, errors: new Map() }), /requires the setup components/);
  assert.match(legacy.renderOnChainRootSummaryHtml([]), /On-chain organizational root \(covenant-enforced M-of-N\)/);
  assert.match(legacy.renderOnChainRootSummaryHtml([{ rootCovenantId: "r".repeat(64), label: "Acme", ownerSlotsActive: 3, ownerM: "2", frozen: false }]), /2 of 3 owners/);
});

test("rc15 review F-01: a SIGNED (already finalized) request is NEVER offered Finalize again — gate closed, button disabled, finalizeRequest refuses BEFORE the wallet; Submit stays available", async () => {
  const api = fakeApi();
  const m = orgRootUiMod.createModule({ api, core, setup: setupMod.createModule({ core }) });
  const owner = "kaspatest:qown1";
  const signedReq = { id: "q1", kind: "rootAction", action: "authorize", state: "SIGNED", signaturesPresent: 2, requiredApprovals: 2, manifest: { action: { requiredApprovals: "2" } }, createdBy: owner, rootInputIndex: 0, slots: [{ slot: 1, publicKey: K(0x71), status: "SIGNED" }, { slot: 2, publicKey: K(0x72), status: "SIGNED" }], transaction: { unsignedSafeJson: "{}", signInputs: [{ index: 0 }, { index: 1 }] } };
  const gate = m.finalizeGate(signedReq);
  assert.equal(gate.enabled, false);
  assert.match(gate.reason, /already finalized/);
  const html = m.renderRequestDetailHtml(signedReq, { viewerAddress: owner });
  const finalizeBtn = (html.match(/<button[^>]*data-rootfinalize[^>]*>/) || [""])[0];
  assert.match(finalizeBtn, /disabled/, "Finalize rendered disabled on a SIGNED request");
  assert.match(finalizeBtn, /already finalized/, "the disabled button explains why");
  const submitBtn = (html.match(/<button[^>]*data-rootsubmit[^>]*>/) || [""])[0];
  assert.doesNotMatch(submitBtn, /disabled/, "Submit to network stays available");
  let signed = 0;
  const adapter = { signInputs: async () => { signed++; return JSON.stringify({ inputs: [{}, { signatureScript: "41" + "ab".repeat(64) + "01" }] }); } };
  await assert.rejects(() => m.finalizeRequest("r", "q1", signedReq, { adapter, network: "testnet-10", expectedSignerAddress: owner }), (e) => e.code === "UNDER_QUORUM" && /already finalized/.test(e.message));
  assert.equal(signed, 0, "the wallet was NOT invoked");
  assert.deepEqual(api.calls.filter((c) => c.method === "POST"), [], "nothing was posted");
  for (const st of ["BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED", "REFUSED", "FAILED", "REJECTED"]) assert.equal(m.finalizeGate({ ...signedReq, state: st }).enabled, false, st);
  assert.equal(m.finalizeGate({ ...signedReq, state: "AUTHORIZED" }).enabled, true, "an AUTHORIZED request at quorum finalizes");
});

test("UX-09 (Codex checkpoint 2): request feedback is derived from the ACTUAL state — slot-derived approval counts (server counter cross-checked, smaller wins), closed descriptions for RECONCILIATION_REQUIRED / FAILED / SUBMISSION_REJECTED / STALE, nested chain outcome and recorded error shown", () => {
  const { m } = mod();
  const base = { id: "q9", kind: "rootAction", action: "authorize", createdBy: "kaspatest:qown1", rootInputIndex: 0, requiredApprovals: "2", manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, publicKey: K(0x71), status: "SIGNED" }, { slot: 2, publicKey: K(0x72), status: "PENDING" }, { slot: 3, publicKey: K(0x73), status: "PENDING" }] };
  // server says 2 signatures but only ONE slot carries one -> "1 of 2" + warning, and finalize stays closed
  const mism = m.renderRequestDetailHtml({ ...base, state: "AUTHORIZED", signaturesPresent: 2 }, { viewerXOnly: K(0x72) });
  assert.match(mism, /1 of 2 collected/);
  assert.match(mism, /warning:<\/b> the server counts 2 but 1 owner slot actually carr/);
  assert.match(mism, /Collect 1 more owner approval/);
  assert.match((mism.match(/<button[^>]*data-rootfinalize[^>]*>/) || [""])[0], /disabled/);
  const g = m.finalizeGate({ ...base, state: "AUTHORIZED", signaturesPresent: 2 });
  assert.equal(g.enabled, false, "the gate is fail-closed on a count mismatch too — the wallet is never asked to sign the fee input");
  assert.match(g.reason, /approval count mismatch \(server 2, owner slots signed 1\)/);
  // partial signatures, consistent
  const partial = m.renderRequestDetailHtml({ ...base, state: "AUTHORIZED", signaturesPresent: 1 }, { viewerXOnly: K(0x72) });
  assert.match(partial, /1 of 2 collected/); assert.doesNotMatch(partial, /warning:/);
  assert.match(partial, /your approval is needed/);
  // RECONCILIATION_REQUIRED: closed description, next action = reconcile, no Finalize/Submit offered
  const rr = m.renderRequestDetailHtml({ ...base, state: "RECONCILIATION_REQUIRED", signaturesPresent: 2, txId: "ab".repeat(32), error: "genesis submit failed: timeout — reconcile" }, { viewerXOnly: K(0x71) });
  assert.match(rr, /Outcome unknown — reconcile before anything else/);
  assert.match(rr, /Reconcile first: use Verify state on the root/);
  assert.match(rr, /Recorded error<\/div><div class="rv-v">genesis submit failed: timeout/);
  assert.match((rr.match(/<button[^>]*data-rootfinalize[^>]*>/) || [""])[0], /disabled/);
  assert.match((rr.match(/<button[^>]*data-rootsubmit[^>]*>/) || [""])[0], /disabled/);
  for (const [st, title] of [["FAILED", "Failed — nothing verified"], ["SUBMISSION_REJECTED", "Rejected by the network"], ["STALE", "Stale — the root moved on"], ["SOMETHING_NEW", "Outcome NOT confirmed"]]) {
    const html = m.renderRequestDetailHtml({ ...base, state: st, signaturesPresent: 2 }, {});
    assert.match(html, new RegExp(title), st);
    assert.equal(m.isVerifiedRequestOutcome(st), false, `${st} is never success`);
  }
  // CHAIN_VERIFIED with the nested chain outcome
  const done = m.renderRequestDetailHtml({ ...base, state: "CHAIN_VERIFIED", signaturesPresent: 2, slots: base.slots.map((x) => ({ ...x, status: "SIGNED" })), chain: { predecessorOutpoint: "aa".repeat(32) + ":0", successorOutpoint: "bb".repeat(32) + ":0", observedAt: "2026-09-05T00:00:00.000Z" } }, {});
  assert.match(done, /Chain outcome<\/div><div class="rv-v">predecessor a{64}:0 consumed; successor b{64}:0 observed at 2026-09-05T00:00:00.000Z/);
  const doneNoChain = m.renderRequestDetailHtml({ ...base, state: "CHAIN_VERIFIED", signaturesPresent: 2 }, {});
  assert.match(doneNoChain, /no chain outpoints are attached to this request/);
});

test("UX-10 (Codex checkpoint 2): a succession request survives a wallet rejection — the SAME durable request is signed on resume; no duplicate creation, no withdrawal", async () => {
  const { api, m } = mod();
  const manifest = manifestOf("root_succession");
  const successor = manifest.ownerSet.after.slots[0].publicKey;
  const request = { id: "s1", rootCovenantId: manifest.root.covenantId, kind: "rootAction", action: "succession", state: "AUTHORIZED", rootInputIndex: 0, manifest, transaction: { unsignedSafeJson: safeJsonFromManifest(manifest), signInputs: [{ index: 0, sighashType: 1 }] } };
  let rejected = 0;
  const rejecting = { signInputs: async () => { rejected++; throw Object.assign(new Error("user rejected"), { code: "USER_REJECTED" }); } };
  await assert.rejects(() => m.signSingleSignerRequest({ request, adapter: rejecting, network: "testnet-10", expectedSignerAddress: "kaspa:qsucc", connectedXOnly: successor }), (e) => e.code === "USER_REJECTED");
  assert.equal(rejected, 1);
  assert.deepEqual(api.calls.filter((c) => c.method === "POST"), [], "a wallet rejection neither withdraws nor re-creates the request");
  const signed = JSON.parse(request.transaction.unsignedSafeJson); signed.inputs[0].signatureScript = `41${"aa".repeat(64)}01`;
  api.postJSON = async (p, body) => { api.calls.push({ method: "POST", path: p, body }); return { request: { ...request, state: "SIGNED" } }; };
  const res = await m.signSingleSignerRequest({ request, adapter: { signInputs: async () => JSON.stringify(signed) }, network: "testnet-10", expectedSignerAddress: "kaspa:qsucc", connectedXOnly: successor });
  assert.equal(res.request.state, "SIGNED");
  const posts = api.calls.filter((c) => c.method === "POST").map((c) => c.path);
  assert.deepEqual(posts, [`/org-roots/${manifest.root.covenantId}/requests/s1/signature`], "resume signs the SAME request id; nothing else was created");
});

test("Codex checkpoint 3 (UX-09): outcome descriptions follow the actual state AND count — partial collection never says nobody approved; SIGNED says finalized/not broadcast; the nested reconciliation outcome is rendered truthfully", () => {
  const { m } = mod();
  assert.match(m.requestOutcome("AUTHORIZED", { present: 0, required: 2 }).title, /no owner has approved yet/);
  assert.match(m.requestOutcome("AUTHORIZED", { present: 1, required: 2 }).title, /1 of 2 approvals collected/);
  assert.match(m.requestOutcome("AUTHORIZED", { present: 1, required: 2 }).meaning, /1 owner slot approved so far; 1 more is needed/);
  assert.match(m.requestOutcome("AUTHORIZED", { present: 2, required: 2 }).title, /ready to finalize/);
  assert.match(m.requestOutcome("SIGNED").title, /Finalized — NOT yet broadcast/);
  assert.match(m.requestOutcome("SIGNED").meaning, /fee input is signed and the transaction is assembled. It has NOT been sent/);
  for (const st of ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "RECONCILIATION_REQUIRED", "WHATEVER"]) assert.notEqual(m.requestOutcome(st, { present: 3, required: 2 }).level, "verified", st);
  const base = { id: "q", kind: "rootAction", action: "authorize", createdBy: "kaspatest:qown1", rootInputIndex: 0, requiredApprovals: "2", manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, publicKey: K(0x71), status: "SIGNED" }, { slot: 2, publicKey: K(0x72), status: "PENDING" }] };
  const html = m.renderRequestDetailHtml({ ...base, state: "AUTHORIZED", signaturesPresent: 1 }, {});
  assert.match(html, /Authorized — 1 of 2 approvals collected/); assert.doesNotMatch(html, /No owner has signed yet/);
  const signed = m.renderRequestDetailHtml({ ...base, state: "SIGNED", signaturesPresent: 2, slots: base.slots.map((x) => ({ ...x, status: "SIGNED" })) }, {});
  assert.match(signed, /Finalized — NOT yet broadcast/); assert.doesNotMatch(signed, /not been assembled/);
  // nested reconciliation outcomes (POST /org-roots/:id/reconcile → { reconcile: { root: { status } } })
  const d = (root) => m.describeReconcileOutcome({ reconcile: { root, vaults: [] } });
  assert.deepEqual([d({ status: "CONSISTENT" }).level, d({ status: "ADVANCED", txId: "ab" }).level], ["good", "good"]);
  assert.equal(d({ status: "CLAIM_PENDING", claimTxId: "cd", ageMs: 5000 }).level, "warn"); assert.match(d({ status: "CLAIM_PENDING", claimTxId: "cd", ageMs: 5000 }).text, /NOT verified: a submitted transaction is still pending \(cd\), 5 s old/);
  assert.equal(d({ status: "UNKNOWN", reason: "claim present" }).level, "bad"); assert.match(d({ status: "UNKNOWN", reason: "claim present" }).text, /Outcome UNKNOWN[^]*do not start a replacement/);
  assert.equal(d({ status: "CLAIM_RELEASED", claimTxId: "ef" }).level, "warn");
  assert.equal(d({ status: "NO_LIVE_OUTPOINT" }).level, "warn");
  assert.equal(m.describeReconcileOutcome({ orgRoot: {} }).level, "bad", "a response without a nested status is NOT verified");
  assert.equal(m.describeReconcileOutcome(null).level, "bad");
});

test("Codex checkpoint 3 (UX-08): recovery-off wording accounts for an enabled successor everywhere — root detail, setup live summary, new-owner-set help — and no 'full quorum' remains", async () => {
  const { m, setup } = mod();
  const withSucc = rootRecord({ template: { ...rootRecord().template, successorPk: K(0xa1), successionEnabled: true } });
  const noSucc = rootRecord({ template: { ...rootRecord().template, successorPk: "00".repeat(32), successionEnabled: false } });
  for (const r of [withSucc, noSucc]) r.state = { ...r.state, recoveryM: "0" };
  const detailSucc = m.renderRootDetailHtml(withSucc, {});
  assert.match(detailSucc, /off — if too many keys are lost, only the designated successor can regain control/);
  assert.doesNotMatch(detailSucc, /control cannot be regained/);
  const detailNo = m.renderRootDetailHtml(noSucc, {});
  assert.match(detailNo, /off — if too many keys are lost, control cannot be regained/);
  const C = m.ROOT_COPY;
  assert.doesNotMatch(C.RECOVERY(1, 3, "about 30 days"), /full quorum/);
  assert.match(C.RECOVERY(1, 3, "about 30 days"), /own approval quorum \(M of N of the new set\)/);
  const live = setup.rootRulesSummary({ ...draft(), recoveryEnabled: false, successionEnabled: true, successorAddress: "kaspatest:qsucc" });
  assert.match(live.join(" "), /only the designated successor can regain control/);
  const liveNo = setup.rootRulesSummary({ ...draft(), recoveryEnabled: false, successionEnabled: false, successorAddress: "" });
  assert.match(liveNo.join(" "), /nobody can regain control/);
  assert.doesNotMatch([detailSucc, detailNo, live.join(" "), m.ROOT_COPY.SUCCESSION("x"), m.ROOT_COPY.RECOVERY(1, 3, "y")].join(" "), /full quorum/);
});

test("rc19 review R4-05: a malformed server fee renders DO NOT SIGN (never throws) on the genesis review", async () => {
  const { m } = mod();
  const { norm } = await m.validateGenesisDraft(draft(), { connectedAddress: "kaspatest:qfunder" });
  const summary = serverSummaryFor(norm);
  for (const bad of [null, "abc", "1.5", "", ["208300"], 208300, undefined]) { // rc20 review R5-05: coerced arrays/numbers and an OMITTED fee are unsignable too
    const sm = { ...summary, requiredFeeSompi: bad }; if (bad === undefined) delete sm.requiredFeeSompi;
    const html = m.renderGenesisReviewHtml({ norm, summary: sm, crossCheck: { ok: true, mismatches: [] }, connectedAddress: "kaspatest:qfunder" });
    assert.match(html, /DO NOT SIGN — the server reported no valid network fee/, `fee ${JSON.stringify(bad)}`);
    assert.doesNotMatch(html, /CHECKED — PolicyVault's description/);
  }
});


test("RC28 UX-08: recovery help and owner-change summary retain the installed succession path", () => {
  const { m } = mod();
  const help = (html) => html.match(/data-help="recovery">([^<]*)<\/div>/)[1];
  for (const successionEnabled of [true, false]) {
    const d = draft({ recoveryEnabled: false, successionEnabled, successorAddress: successionEnabled ? "kaspatest:qsucc" : "" });
    const root = rootRecord({ template: { ...rootRecord().template, successorPk: successionEnabled ? K(0xa1) : "00".repeat(32) } });
    const setup = help(m.renderGenesisSetupHtml({ draft: d, step: 2, errors: new Map(), connectedAddress: "kaspatest:qfunder", network: "testnet-10" }));
    const owner = help(m.renderNewOwnerSetHtml({ action: "rotate", orgRoot: root, draft: d, errors: new Map(), connectedAddress: "kaspatest:qown1" }));
    for (const text of [setup, owner]) {
      if (successionEnabled) {
        assert.doesNotMatch(text, /can no longer be closed|stays locked|no one can regain/);
        assert.match(text, /installed owners.*unfreeze.*approval quorum/);
        assert.match(text, /manage and close.*vaults/);
      } else assert.match(text, /no one can regain control.*stays locked/);
    }
    const summary = m.newOwnerSetSummary(d, root).join(" ");
    if (successionEnabled) { assert.match(summary, /designated successor can regain control/); assert.doesNotMatch(summary, /nobody can regain/); }
    else assert.match(summary, /nobody can regain control/);
  }
});


test("RC28 UX-08: fixed recovery delay, retained keys and heartbeat quorum remain truthful in confirmations", () => {
  const { m } = mod();
  const root = rootRecord({ template: { ...rootRecord().template, recoveryDelayDaa: "6048000", successorPk: K(0xa1) } });
  const d = m.newOwnerSetDraftFrom(root, { action: "rotate" });
  const summary = m.newOwnerSetSummary(d, root).join(" ");
  assert.match(summary, /about 7 days/); assert.doesNotMatch(summary, /30 days/);
  const rendered = m.renderNewOwnerSetHtml({ action: "rotate", orgRoot: root, draft: d, errors: new Map(), connectedAddress: "kaspatest:qown1" });
  assert.match(rendered, /about 7 days/); assert.doesNotMatch(rendered, /30 days/);
  for (const action of ["ownerRecover", "succession"]) {
    const html = m.renderDangerousConfirmHtml({ action, rootLabel: "Acme", orgRoot: root });
    assert.doesNotMatch(html, /FULL quorum|full owner set|at any time|none of the previous owner keys/);
    assert.match(html, /unfrozen/); assert.match(html, /approval quorum/);
    if (action === "succession") assert.match(html, /previous owner.*listed again/);
  }
});
