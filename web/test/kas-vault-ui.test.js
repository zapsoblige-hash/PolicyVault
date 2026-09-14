"use strict";
/*
 * BROWSER layer — v0.7 mainnet enablement (2026-09-10): the ROOTED KAS
 * TREASURY browser path (web/kas-vault-ui.js + the KAS profile dispatch in
 * web/org-root-ui.js) against the committed core bundle and the REAL
 * production-byte KAS fixtures (core/explain/test/fixtures/v7-kas-manifests.json:
 * silverc-compiled treasury, SDK-built genesis / owner-operation / delegate
 * payment transactions). Every signing path must (1) re-verify locally with
 * the predecessor redeem bound, (2) bind the wallet payload to the reviewed
 * frozen bytes, (3) refuse BEFORE the wallet on any substitution, and (4) for a
 * genesis, rebuild the treasury's locking script from the reviewed rules and
 * refuse a different destination. Headless (no DOM): the modules are pure
 * HTML-string renderers + validators, exactly as the app consumes them.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO = path.join(__dirname, "..", "..");
const core = require("../core-bundle.js");
const setupMod = require("../setup-ui.js");
const kasMod = require("../kas-vault-ui.js");
const orgRootUiMod = require("../org-root-ui.js");
const FX = JSON.parse(fs.readFileSync(path.join(REPO, "core/explain/test/fixtures/v7-kas-manifests.json"), "utf8"));
const KAS = "policyvault-0.7-kas";
const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const SENTINEL = "00".repeat(32);
const fixture = (name) => { const f = FX.manifests.find((x) => x.name === name); assert.ok(f, `fixture ${name}`); return f; };
const spendFixture = (name) => { const f = FX.spends.find((x) => x.name === name); assert.ok(f, `spend fixture ${name}`); return f; };

function fakeApi(overrides = {}) {
  const calls = [];
  const responses = new Map(Object.entries(overrides));
  return {
    calls,
    on(key, value) { responses.set(key, value); return this; },
    async getJSON(p) { calls.push({ method: "GET", path: p }); const r = responses.get(`GET ${p}`); if (r === undefined) throw Object.assign(new Error(`no fake response for GET ${p}`), { code: "FAKE_UNMAPPED" }); return typeof r === "function" ? r() : r; },
    async postJSON(p, body) { calls.push({ method: "POST", path: p, body }); const r = responses.get(`POST ${p}`); if (r === undefined) throw Object.assign(new Error(`no fake response for POST ${p}`), { code: "FAKE_UNMAPPED" }); return typeof r === "function" ? r(body) : r; },
    async resolveXOnly(address) { const m = /^kaspa(?:test)?:q([0-9a-f]{64})$/.exec(address); if (!m) throw new Error(`unresolvable ${address}`); return m[1]; }
  };
}
function mods(api = fakeApi()) {
  const setup = setupMod.createModule({ core });
  const rootUI = orgRootUiMod.createModule({ api, core, setup });
  const km = kasMod.createModule({ api, core, setup, payload: { parseSigningPayload: rootUI.parseSigningPayload, frozenMismatches: rootUI.frozenMismatches } });
  const rootWithKas = orgRootUiMod.createModule({ api, core, setup, kas: km });
  return { setup, rootUI: rootWithKas, km, api };
}
function mockAdapter(signedByte = 0xaa) {
  const calls = [];
  return { calls, async signInputs(unsignedSafeJson, entries) { calls.push({ unsignedSafeJson, entries }); const t = JSON.parse(unsignedSafeJson); for (const e of entries) t.inputs[e.index].signatureScript = `41${signedByte.toString(16).padStart(2, "0").repeat(64)}01`; return JSON.stringify(t); } };
}

/* ---- the treasury as the server presents it (GET /org-roots/:id/vaults, GET /wallet/v7/vaults) ---- */
const G = FX.genesis;
const AGENT = FX.spends[0].manifest.policy.agentPolicy.agentPk;
const APPROVERS = FX.spends.find((s) => s.aboveThreshold).manifest.approverTier.activeApprovers;
const VAULT = {
  vaultId: G.summary.vaultId, label: "Ops treasury", status: "ACTIVE", orgRootCovenantId: G.summary.orgRootCovenantId, contractVersion: KAS, candidateStatus: "CANDIDATE", profile: "kas", generation: 1,
  recoveryPk: G.summary.recoveryPk, agents: G.summary.agents, approvers: APPROVERS, approvalM: String(G.summary.initialState.approvalM),
  live: { covenantId: G.summary.covenantId, outpoint: { transactionId: G.txId, index: 0 }, protectedValueKas: "100", feeReserveKas: "5", totalKas: "105", paused: false, policyNonce: "0" }
};
const OWNER = K(0x71);
const ROOT = { rootCovenantId: G.summary.orgRootCovenantId, label: "Acme", networkId: "testnet-10", state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1", rootNonce: "0" }, slots: [{ slot: 1, publicKey: OWNER, address: "kaspa:qown1" }, { slot: 2, publicKey: K(0x72), address: "kaspa:qown2" }], template: {}, vaults: [VAULT.vaultId], pendingRequestId: null, live: { outpoint: { transactionId: "bb".repeat(32), index: 0 } } };
const normFromSummary = (sum) => ({ label: "", protectedSompi: BigInt(sum.initialState.protectedValue), feeReserveSompi: BigInt(sum.initialState.feeReserve), agents: sum.agents.map((a) => ({ ...a })), agentRoot: sum.initialState.agentRoot, approvers: sum.initialState.approverSlots.filter((k) => k !== SENTINEL), approvalM: String(sum.initialState.approvalM), recoveryPk: sum.recoveryPk, rootPins: { orgRootCovenantId: G.summary.orgRootCovenantId, networkId: G.summary.networkId, ...Object.fromEntries(["rootTemplateVmHash", "rootPrefixLen", "rootStateLen", "rootSuffixLen"].map((k) => [k, G.summary.template[k]])) } });
const genesisRequest = () => ({ requestId: "g1", kind: "kasGenesis", state: "BUILT", contractVersion: KAS, summary: G.summary, signerXOnly: G.funderXOnly, transaction: { unsignedSafeJson: G.unsignedSafeJson, signInputs: G.signInputs, frozenCanonicalJson: G.frozenCanonicalJson } });
const spendRequest = (fx, state) => ({ requestId: `s-${fx.name}`, kind: "agentSpend", state: state || (fx.aboveThreshold ? "AWAITING_APPROVALS" : "BUILT"), contractVersion: KAS, vaultId: VAULT.vaultId, manifest: fx.manifest, redeemScripts: fx.redeemScripts, signerXOnly: fx.manifest.policy.agentPolicy.agentPk, aboveThreshold: fx.aboveThreshold, transaction: { unsignedSafeJson: fx.unsignedSafeJson, signInputs: fx.signInputs, covenantInputIndex: fx.covenantInputIndex, frozenCanonicalJson: fx.frozenCanonicalJson }, review: { amountKas: fx.manifest.accounting.kas ? undefined : undefined, recipient: fx.manifest.policy.recipient } });

/* ==================== owner-operation table + profile dispatch ==================== */
test("the KAS owner-operation table agrees with the SHARED CORE's authority map; an unknown / foreign-profile op is never offered", () => {
  const { km, rootUI } = mods();
  const table = core.vaultStateV7Kas.OWNER_OP_ROOT_AUTHORITY_V7_KAS;
  assert.equal(km.VAULT_OP_ORDER.length, 8);
  for (const op of km.VAULT_OP_ORDER) {
    const info = km.vaultOpInfo(op);
    assert.ok(info, `${op} known`);
    assert.equal(info.rootAction, core.vaultStateV7Kas.resolveOwnerOpAuthorityV7Kas(op).rootActionName, `${op} root action`);
    assert.ok(Object.prototype.hasOwnProperty.call(table, op) || core.vaultStateV7Kas.resolveOwnerOpAuthorityV7Kas(op), `${op} in the core table`);
    assert.ok(info.describe.length > 40, `${op} carries a plain-language consequence`);
  }
  assert.equal(km.vaultOpInfo("tokenAgentSpend"), null);
  assert.equal(km.vaultOpInfo("ownerSetAgentRoot; DROP"), null);
  /* org-root-ui dispatches by profile: the KAS-only ops exist ONLY for the KAS profile */
  assert.equal(rootUI.vaultOpInfo("ownerSetApprovers"), null, "payment profile has no approver tier op");
  assert.equal(rootUI.vaultOpInfo("ownerTopUp"), null);
  assert.ok(rootUI.vaultOpInfo("ownerSetApprovers", KAS));
  assert.ok(rootUI.vaultOpInfo("ownerTopUp", KAS));
  assert.equal(rootUI.vaultOpInfo("ownerSetAgentRoot", KAS).form, "kasAgents");
  assert.equal(rootUI.vaultOpConfirmPhrase("ownerRecover"), "CONFIRM CLOSE VAULT");
  assert.equal(km.vaultOpConfirmPhrase("ownerRecover"), "CONFIRM CLOSE TREASURY");
});

test("availability: KAS owner ops follow the root role / pending / frozen rules; on MAINNET they need this release's discovery to say mainnetOperable (fail closed otherwise); the token profile stays off mainnet", () => {
  const { rootUI } = mods();
  const on = (over = {}, root = ROOT, extra = {}) => rootUI.vaultOpAvailability({ op: "ownerPause", vault: { ...VAULT, ...over }, orgRoot: root, viewerXOnly: OWNER, networkId: root.networkId, ...extra });
  assert.deepEqual(on(), { enabled: true, offered: true, reason: "" });
  assert.equal(rootUI.vaultOpAvailability({ op: "ownerPause", vault: VAULT, orgRoot: ROOT, viewerXOnly: K(0x55), networkId: "testnet-10" }).enabled, false, "a non-owner cannot start");
  assert.match(on({}, { ...ROOT, pendingRequestId: "p1" }).reason, /already pending/);
  assert.match(on({}, { ...ROOT, state: { ...ROOT.state, frozen: 1 } }).reason, /FROZEN/);
  assert.match(on({ live: { ...VAULT.live, paused: true } }).reason, /already paused/);
  assert.equal(rootUI.vaultOpAvailability({ op: "ownerUnpause", vault: { ...VAULT, live: { ...VAULT.live, paused: true } }, orgRoot: ROOT, viewerXOnly: OWNER, networkId: "testnet-10" }).enabled, true);
  assert.equal(rootUI.vaultOpAvailability({ op: "ownerSetApprovers", vault: VAULT, orgRoot: ROOT, viewerXOnly: OWNER, networkId: "testnet-10" }).enabled, true);
  const mainRoot = { ...ROOT, networkId: "mainnet" };
  const noCaps = on({}, mainRoot);
  assert.equal(noCaps.enabled, false); assert.equal(noCaps.offered, true); assert.match(noCaps.reason, /could not be confirmed/);
  const foreign = on({}, mainRoot, { capabilities: { networkId: "testnet-10", contract: { covenantVersions: [{ contractVersion: KAS, mainnetOperable: true }] } } });
  assert.equal(foreign.enabled, false, "a discovery for ANOTHER network never enables mainnet");
  const notOperable = on({}, mainRoot, { capabilities: { networkId: "mainnet", contract: { covenantVersions: [{ contractVersion: KAS, mainnetOperable: false }] } } });
  assert.equal(notOperable.enabled, false);
  const ok = on({}, mainRoot, { capabilities: { networkId: "mainnet", contract: { covenantVersions: [{ contractVersion: KAS, mainnetOperable: true }] } } });
  assert.equal(ok.enabled, true, "mainnetOperable from this release's discovery enables the control (the server + SDK re-decide)");
  const payment = rootUI.vaultOpAvailability({ op: "ownerPause", vault: { ...VAULT, contractVersion: "policyvault-0.7-payment", live: { ...VAULT.live, tokenPosition: null } }, orgRoot: mainRoot, viewerXOnly: OWNER, networkId: "mainnet", capabilities: { networkId: "mainnet", contract: { covenantVersions: [{ contractVersion: "policyvault-0.7-payment", mainnetOperable: true }] } } });
  assert.equal(payment.enabled, false); assert.match(payment.reason, /not mainnet-authorized/);
  assert.equal(rootUI.vaultOpAvailability({ op: "ownerPause", vault: { ...VAULT, contractVersion: "policyvault-0.8-x" }, orgRoot: ROOT, viewerXOnly: OWNER }).offered, false, "an unknown profile is not offered at all");
});

test("root creation availability = root + a creatable rooted profile (KAS or token); KAS treasury creation availability is discovery-bound per network", () => {
  const { rootUI } = mods();
  const caps = (networkId, versions) => ({ networkId, capabilities: { networkId, contract: { creatableCovenantVersions: versions } } });
  assert.equal(rootUI.rootCreationAvailability(caps("mainnet", ["policyvault-0.4.1", "policyvault-0.7-root", KAS])).enabled, true, "root + KAS (the reviewed mainnet set) offers root creation");
  assert.equal(rootUI.rootCreationAvailability(caps("testnet-10", ["policyvault-0.7-root", "policyvault-0.7-payment"])).enabled, true);
  assert.equal(rootUI.rootCreationAvailability(caps("mainnet", ["policyvault-0.4.1", "policyvault-0.7-root"])).enabled, false, "a root with no creatable rooted profile is not offered");
  assert.equal(rootUI.rootCreationAvailability(caps("mainnet", ["policyvault-0.4.1", KAS])).enabled, false);
  assert.equal(rootUI.kasCreationAvailability(caps("mainnet", ["policyvault-0.4.1", "policyvault-0.7-root", KAS])).enabled, true);
  assert.equal(rootUI.kasCreationAvailability(caps("mainnet", ["policyvault-0.4.1", "policyvault-0.7-root"])).enabled, false);
  assert.match(rootUI.kasCreationAvailability({ networkId: "mainnet", capabilities: null }).reason, /could not be confirmed/);
  assert.equal(rootUI.kasCreationAvailability({ networkId: "mainnet", capabilities: { networkId: "testnet-10", contract: { creatableCovenantVersions: [KAS] } } }).enabled, false, "foreign-network discovery never enables");
});

/* ==================== treasury panel + request cards + participant list ==================== */
test("the treasury panel states ownership, candidate status, live balances, delegate rules, the approver tier and the pinned recovery key; Pay is offered to a delegate only; owner ops through availability", () => {
  const { rootUI, km } = mods();
  const ownerView = rootUI.renderRootedVaultOwnerOpsHtml(VAULT, ROOT, { viewerXOnly: OWNER, networkId: "testnet-10", loaded: true });
  assert.match(ownerView, /data-vault-profile="policyvault-0.7-kas"/);
  assert.match(ownerView, /KAS treasury · candidate profile/);
  assert.ok(ownerView.includes(km.OWNERSHIP_STATEMENT.slice(0, 40)), "the ownership statement is on the panel");
  assert.match(ownerView, /100 KAS protected · 5 KAS fee reserve/);
  assert.match(ownerView, /Pinned recovery key/);
  assert.ok(ownerView.includes(G.summary.recoveryPk));
  assert.doesNotMatch(ownerView, /data-kasspend=/, "an owner who is not a delegate gets no Pay control");
  for (const op of km.VAULT_OP_ORDER) if (op !== "ownerUnpause") assert.ok(ownerView.includes(`data-rootvaultop="${op}"`), `${op} offered to the owner`);
  assert.match(ownerView, /<button type="button" disabled class="" data-rootvaultop="ownerUnpause"/, "unpause is offered but disabled on an unpaused treasury");
  const agentView = rootUI.renderRootedVaultOwnerOpsHtml(VAULT, ROOT, { viewerXOnly: AGENT, networkId: "testnet-10", loaded: true });
  assert.match(agentView, /data-kasspend=/, "a delegate gets Pay from this treasury");
  assert.match(agentView, /\(you\)/);
  assert.match(agentView, /<button type="button" disabled class="" data-rootvaultop="ownerPause"/, "a delegate who is not an owner cannot start an owner operation");
  const paused = rootUI.renderRootedVaultOwnerOpsHtml({ ...VAULT, live: { ...VAULT.live, paused: true } }, ROOT, { viewerXOnly: AGENT, networkId: "testnet-10", loaded: true });
  assert.doesNotMatch(paused, /data-kasspend=/, "no Pay on a paused treasury");
  assert.match(paused, /PAUSED — delegate payments stopped/);
  const notLoaded = rootUI.renderRootedVaultOwnerOpsHtml({ vaultId: VAULT.vaultId, contractVersion: KAS }, ROOT, { viewerXOnly: OWNER, loaded: false });
  assert.doesNotMatch(notLoaded, /data-rootvaultop=/, "nothing is offered when the state could not be loaded");
});

test("request cards: an approver sees Review & approve only while AWAITING_APPROVALS and not yet approved; the delegate signs at BUILT and withdraws; SIGNED offers Submit; final states carry their truthful outcome", () => {
  const { km } = mods();
  const above = spendFixture("delegate_spend_above_threshold");
  const req = { ...spendRequest(above), approvalProgress: { collected: 0, required: 1, complete: false, approverSlots: APPROVERS, approvedSlots: [false, false] }, review: { amountKas: "3", recipient: above.manifest.policy.recipient } };
  assert.match(km.renderKasRequestCardHtml(VAULT, req, { viewerXOnly: APPROVERS[0] }), /data-kasapprove="s-delegate_spend_above_threshold"/);
  assert.match(km.renderKasRequestCardHtml(VAULT, { ...req, approvalProgress: { ...req.approvalProgress, collected: 1, approvedSlots: [true, false] } }, { viewerXOnly: APPROVERS[0] }), /You approved — waiting/);
  assert.doesNotMatch(km.renderKasRequestCardHtml(VAULT, req, { viewerXOnly: K(0x55) }), /data-kasapprove=|data-kasagentsign=/, "a stranger gets no action");
  assert.match(km.renderKasRequestCardHtml(VAULT, req, { viewerXOnly: AGENT }), /Approvers sign first/);
  assert.match(km.renderKasRequestCardHtml(VAULT, req, { viewerXOnly: AGENT }), /data-kascancel=/);
  const below = spendFixture("delegate_spend_below_threshold");
  const built = { ...spendRequest(below), approvalProgress: { collected: 0, required: 0, complete: true, approverSlots: null, approvedSlots: [] }, review: { amountKas: "1", recipient: below.manifest.policy.recipient } };
  assert.match(km.renderKasRequestCardHtml(VAULT, built, { viewerXOnly: AGENT }), /data-kasagentsign=/);
  assert.match(km.renderKasRequestCardHtml(VAULT, { ...built, state: "SIGNED" }, { viewerXOnly: AGENT }), /data-kassubmit=/);
  assert.match(km.renderKasRequestCardHtml(VAULT, { ...built, state: "SUBMITTED" }, { viewerXOnly: AGENT }), /NOT yet confirmed/);
  assert.match(km.renderKasRequestCardHtml(VAULT, { ...built, state: "CHAIN_VERIFIED" }, { viewerXOnly: AGENT }), /Chain-verified/);
  assert.match(km.renderKasRequestCardHtml(VAULT, { ...built, state: "RECONCILIATION_REQUIRED" }, { viewerXOnly: AGENT }), /Outcome unknown/);
  assert.match(km.renderKasRequestCardHtml(VAULT, { ...built, state: "SOMETHING_NEW" }, { viewerXOnly: AGENT }), /not confirmed/, "an unknown state is never presented as success");
});

test("the participant section lists only KAS treasuries where the viewer is a delegate or an approver, without owner operations", () => {
  const { km, rootUI } = mods();
  assert.equal(km.renderParticipantVaultsHtml([VAULT], { viewerXOnly: OWNER }), "", "an owner finds treasuries on the root detail, not here");
  const asAgent = km.renderParticipantVaultsHtml([VAULT, { ...VAULT, vaultId: K(0x45), contractVersion: "policyvault-0.7-payment" }], { viewerXOnly: AGENT });
  assert.match(asAgent, /data-kas-participant-vaults="1"/);
  assert.match(asAgent, /data-kasspend=/);
  assert.doesNotMatch(asAgent, /data-rootvaultop=/);
  const asApprover = km.renderParticipantVaultsHtml([VAULT], { viewerXOnly: APPROVERS[1] });
  assert.match(asApprover, /you are an approver/);
  const summary = rootUI.renderOnChainRootSummaryHtml([], { networkId: "testnet-10", capabilities: { networkId: "testnet-10", contract: { creatableCovenantVersions: ["policyvault-0.7-root", KAS] } } }, { participantVaults: [VAULT], viewerXOnly: AGENT });
  assert.match(summary, /KAS treasuries you take part in/);
});

test("the root detail offers Create KAS treasury to an owner when discovery allows it, and never on a frozen / pending / unconfirmed root or to a non-owner", () => {
  const { rootUI } = mods();
  const ctx = { networkId: "testnet-10", capabilities: { networkId: "testnet-10", contract: { creatableCovenantVersions: ["policyvault-0.7-root", KAS] } } };
  const html = rootUI.renderRootDetailHtml(ROOT, { viewerXOnly: OWNER, rootedVaults: [VAULT], creationContext: ctx });
  assert.match(html, /<button type="button" class="primary" data-kascreate="[0-9a-f]{64}"/);
  assert.match(html, /data-vault-profile="policyvault-0.7-kas"/, "the KAS treasury panel renders inside the root detail");
  assert.match(rootUI.renderRootDetailHtml(ROOT, { viewerXOnly: K(0x55), rootedVaults: [VAULT], creationContext: ctx }), /<button type="button" disabled class="primary" data-kascreate=/);
  assert.match(rootUI.renderRootDetailHtml({ ...ROOT, state: { ...ROOT.state, frozen: 1 } }, { viewerXOnly: OWNER, rootedVaults: [VAULT], creationContext: ctx }), /disabled class="primary" data-kascreate=/);
  assert.match(rootUI.renderRootDetailHtml({ ...ROOT, pendingRequestId: "p1" }, { viewerXOnly: OWNER, rootedVaults: [VAULT], creationContext: ctx }), /disabled class="primary" data-kascreate=/);
  const noDiscovery = rootUI.renderRootDetailHtml(ROOT, { viewerXOnly: OWNER, rootedVaults: [VAULT], creationContext: { networkId: "testnet-10", capabilities: null } });
  assert.match(noDiscovery, /disabled class="primary" data-kascreate=/);
  assert.match(noDiscovery, /could not be confirmed/);
});

/* ==================== creation wizard: drafts, validation, summaries, cross-check, BINDING ==================== */
test("wizard validation: per-step errors; a full validation normalizes the rules (agent root == the core's Merkle root of the exact policies)", async () => {
  const { km } = mods();
  const d = km.kasDraftDefaults("kaspa:q" + G.funderXOnly, "5000");
  let v = await km.validateKasDraft(d, { step: "treasury", connectedAddress: "kaspa:q" + G.funderXOnly });
  assert.ok(v.errors.has("depositKas"));
  d.depositKas = "100"; d.feeReserveKas = "5"; d.label = "Ops";
  v = await km.validateKasDraft(d, { step: "treasury" }); assert.equal(v.errors.size, 0);
  d.agents = [{ agentKey: AGENT, maxPerSpendKas: "10", periodBudgetKas: "100", periodLengthDaa: "864000", periodStartDaa: "0", periodSpent: "0", approvalThresholdKas: "2", agentMaxFeePerTxKas: "0.05", recipients: `${K(0x71)}\n${K(0x72)}` }];
  v = await km.validateKasDraft(d, { step: "delegates" }); assert.equal(v.errors.size, 0, [...v.errors]);
  d.agents[0].agentMaxFeePerTxKas = "0.02";
  v = await km.validateKasDraft(d, { step: "delegates" });
  assert.match(v.errors.get("agentRows")[0].agentMaxFeePerTxKas, /about 0\.04 KAS.*at least|below 0\.05 KAS/, "a fee cap below the treasury's real payment fee is refused up front (lane-01 harness finding: OVER_AGENT_FEE_CAP at build time)");
  d.agents[0].agentMaxFeePerTxKas = "0.05";
  d.agents.push({ ...d.agents[0], maxPerSpendKas: "1000" });
  v = await km.validateKasDraft(d, { step: "delegates" });
  assert.ok(v.errors.has("agentRows")); assert.match(v.errors.get("agentRows")[1].agentKey, /already listed/); assert.match(v.errors.get("agentRows")[1].maxPerSpendKas, /cannot exceed/);
  d.agents.pop();
  d.approvers = [{ publicKey: APPROVERS[0], keyMode: true }, { publicKey: APPROVERS[1], keyMode: true }]; d.approvalM = "3";
  v = await km.validateKasDraft(d, { step: "approvals" }); assert.match(v.errors.get("approvalM"), /between 1 and 2/);
  d.approvalM = "1";
  v = await km.validateKasDraft(d, { step: "recovery" }); assert.ok(v.errors.has("recoveryAddress"));
  d.recoveryAddress = "kaspa:q" + G.summary.recoveryPk;
  v = await km.validateKasDraft(d, { connectedAddress: "kaspa:q" + G.funderXOnly });
  assert.equal(v.ok, true, [...v.errors]);
  assert.equal(v.norm.protectedSompi, 10000000000n); assert.equal(v.norm.feeReserveSompi, 500000000n);
  const expectedRoot = core.agentMerkle.buildAgentTreeV4([{ agentPk: AGENT, maxPerSpend: "1000000000", periodBudget: "10000000000", periodLengthDaa: "864000", periodStartDaa: "0", periodSpent: "0", approvalThreshold: "200000000", agentMaxFeePerTx: "5000000", agentRecipientRoot: core.recipientMerkle.buildRecipientTree([K(0x71), K(0x72)]).root }]).root;
  assert.equal(v.norm.agentRoot, expectedRoot);
  assert.deepEqual(v.form.approvers, APPROVERS); assert.equal(v.form.approvalM, "1"); assert.equal(v.form.depositKas, "100"); assert.equal(v.form.feeReserveKas, "5");
  assert.equal(v.form.agents[0].recipients.length, 2);
  const html = km.renderKasSetupHtml({ draft: d, step: 3, errors: new Map(), connectedAddress: "kaspa:qx", busy: false, orgRoot: ROOT, network: "testnet-10" });
  assert.match(html, /Irreversible recovery/); assert.match(html, /ENTIRE balance/); assert.match(html, /data-kas-wizard/);
  assert.equal((html.match(/data-setup-step=/g) || []).length, 5);
  const sentences = km.kasRulesSummary(d, ROOT);
  assert.ok(sentences.some((s) => /2 of 2 owners/.test(s)) && sentences.some((s) => /IRREVERSIBLE/.test(s)) && sentences.some((s) => /1 of 2 approver/.test(s)));
});

test("genesis cross-check: the server's summary must match the reviewed rules value for value; a substituted recovery key / approver / delegate rule / amount refuses", () => {
  const { km } = mods();
  const norm = normFromSummary(G.summary);
  assert.deepEqual(km.genesisCrossCheck({ summary: G.summary, norm }), { ok: true, mismatches: [] });
  assert.match(km.genesisCrossCheck({ summary: G.summary, norm: { ...norm, recoveryPk: K(0x99) } }).mismatches.join(";"), /recovery key/);
  assert.match(km.genesisCrossCheck({ summary: G.summary, norm: { ...norm, approvers: [APPROVERS[0]] } }).mismatches.join(";"), /approver set/);
  assert.match(km.genesisCrossCheck({ summary: G.summary, norm: { ...norm, protectedSompi: norm.protectedSompi + 1n } }).mismatches.join(";"), /protected principal/);
  assert.match(km.genesisCrossCheck({ summary: G.summary, norm: { ...norm, agents: norm.agents.map((a) => ({ ...a, maxPerSpend: "1" })) } }).mismatches.join(";"), /maxPerSpend/);
  assert.match(km.genesisCrossCheck({ summary: { ...G.summary, kind: "other" }, norm }).mismatches.join(";"), /did not return/);
  const html = km.renderKasGenesisReviewHtml({ norm, summary: G.summary, crossCheck: { ok: true, mismatches: [] }, connectedAddress: "kaspa:qx" });
  assert.match(html, /VERIFIED — the built treasury matches/); assert.match(html, /Recovery key \(irreversible destination\)/); assert.match(html, /role="status"/);
});

test("genesis BINDING: the wallet payload must be the reviewed transaction AND its output 0 must be the treasury script REBUILT LOCALLY from the reviewed rules; every substitution refuses before the wallet", async () => {
  const { km, api } = mods();
  const norm = normFromSummary(G.summary);
  const crossCheck = km.genesisCrossCheck({ summary: G.summary, norm });
  const req = genesisRequest();
  const base = { request: req, unsignedSafeJson: G.unsignedSafeJson, signInputs: G.signInputs, network: G.summary.networkId, connectedXOnly: G.funderXOnly, crossCheck, norm };
  const bound = km.bindKasGenesisSigningPayload(base);
  assert.equal(bound.ok, true); assert.equal(bound.txId, G.txId); assert.equal(bound.feeSompi, G.requiredFeeSompi);
  assert.equal(bound.vaultSpk, "0000" + core.vaultScriptV7Kas.p2shSpkHexOf(G.vaultScriptHex), "the rebuilt destination is the P2SH of silverc's compiled treasury");
  const refuse = (over, code, re) => assert.throws(() => km.bindKasGenesisSigningPayload({ ...base, ...over }), (e) => { assert.equal(e.code, code, e.message); if (re) assert.match(e.message, re); return true; });
  refuse({ network: "mainnet" }, "NETWORK_MISMATCH");
  refuse({ connectedXOnly: K(0x55) }, "PAYLOAD_MISMATCH", /does not return to your wallet|not your wallet's/);
  refuse({ crossCheck: { ok: false, mismatches: ["x"] } }, "REVIEW_REFUSED");
  refuse({ request: { ...req, summary: { ...G.summary, requiredFeeSompi: String(BigInt(G.requiredFeeSompi) + 1n) } } }, "FEE_MISMATCH");
  refuse({ request: { ...req, summary: { ...G.summary, txId: K(0x01) } } }, "PAYLOAD_MISMATCH", /transaction id differs/);
  /* a treasury whose rules differ from the reviewed ones (other recovery key) — the rebuilt script differs from output 0 */
  const otherRules = { ...G.summary, recoveryPk: K(0x99), template: { ...G.summary.template, recoveryPk: K(0x99) } };
  refuse({ request: { ...req, summary: otherRules }, norm: { ...norm, recoveryPk: K(0x99) }, crossCheck: { ok: true, mismatches: [] } }, "PAYLOAD_MISMATCH", /NOT the script of the rules you reviewed/);
  /* a tampered payload: value moved out of the treasury (the fee no longer matches the review) / the change redirected (frozen bytes differ) */
  const t = JSON.parse(G.unsignedSafeJson); t.outputs[0].value = String(BigInt(t.outputs[0].value) - 1n);
  refuse({ unsignedSafeJson: JSON.stringify(t) }, "FEE_MISMATCH");
  const t2 = JSON.parse(G.unsignedSafeJson); t2.outputs[1].scriptPublicKey = "000020" + K(0x55) + "ac";
  refuse({ unsignedSafeJson: JSON.stringify(t2) }, "PAYLOAD_MISMATCH", /differs from the built transaction/);
  refuse({ signInputs: [] }, "PAYLOAD_INVALID");
  refuse({ request: { ...req, kind: "agentSpend" } }, "REQUEST_NOT_SIGNABLE");
  /* the sign path: adapter invoked only after binding, then the signature posted */
  api.on("POST /wallet/v7/requests/g1/signature", (body) => ({ request: { ...req, state: "SIGNED" }, signed: body.signedSafeJson }));
  const adapter = mockAdapter();
  const res = await km.signKasGenesisRequest({ request: req, adapter, network: G.summary.networkId, expectedSignerAddress: "kaspa:qf", connectedXOnly: G.funderXOnly, crossCheck, norm });
  assert.equal(res.request.state, "SIGNED"); assert.equal(adapter.calls.length, 1); assert.deepEqual(adapter.calls[0].entries, G.signInputs);
  const badAdapter = mockAdapter();
  await assert.rejects(() => km.signKasGenesisRequest({ request: req, adapter: badAdapter, network: G.summary.networkId, expectedSignerAddress: "kaspa:qf", connectedXOnly: K(0x55), crossCheck, norm }), (e) => e.code === "PAYLOAD_MISMATCH");
  assert.equal(badAdapter.calls.length, 0, "the wallet is never invoked on a refused binding");
});

/* ==================== delegate payment + approval: review + BINDING ==================== */
test("delegate payment review re-verifies locally with the predecessor redeem (VERIFIED_EXACT); a tampered amount or a missing redeem is DO NOT SIGN", () => {
  const { km } = mods();
  const below = spendFixture("delegate_spend_below_threshold");
  const req = spendRequest(below);
  const html = km.renderSpendReviewHtml(req);
  assert.match(html, /data-kas-spend-review="verified"/); assert.match(html, /VERIFIED — EXACT PAYMENT BEFORE SIGNING/); assert.match(html, /role="status"/);
  const tampered = JSON.parse(JSON.stringify(below.manifest)); tampered.accounting.kas.payAmount = String(BigInt(tampered.accounting.kas.payAmount) + 1n);
  assert.match(km.renderSpendReviewHtml({ ...req, manifest: tampered }), /data-kas-spend-review="refused"/);
  assert.match(km.renderSpendReviewHtml({ ...req, redeemScripts: {} }), /data-kas-spend-review="refused"/, "R7-04: without the predecessor redeem the successor cannot be reconstructed — refused");
  assert.match(km.renderSpendReviewHtml({ ...req, manifest: null }), /refusing to render a review/);
});

test("spend drafts: a delegate's form is bounded by its OWN installed rule (cap, remaining budget, allowed recipients); a non-delegate cannot build", async () => {
  const { km } = mods();
  const me = VAULT.agents[0];
  assert.equal(km.spendDraftFrom({ vault: VAULT, viewerXOnly: AGENT }).recipient, me.recipients[0]);
  let v = await km.validateSpendDraft({ draft: { amountKas: "1", recipient: me.recipients[0] }, vault: VAULT, viewerXOnly: AGENT });
  assert.equal(v.ok, true); assert.equal(v.params.payAmountSompi, "100000000"); assert.equal(v.preview.aboveThreshold, BigInt("100000000") > BigInt(me.approvalThreshold));
  v = await km.validateSpendDraft({ draft: { amountKas: core.amounts.sompiToKas(BigInt(me.maxPerSpend) + 1n), recipient: me.recipients[0] }, vault: VAULT, viewerXOnly: AGENT });
  assert.match(v.errors.get("amountKas"), /cap/);
  v = await km.validateSpendDraft({ draft: { amountKas: "1", recipient: K(0x99) }, vault: VAULT, viewerXOnly: AGENT });
  assert.match(v.errors.get("recipient"), /not on this delegate's allowed-recipient list/);
  v = await km.validateSpendDraft({ draft: { amountKas: "1", recipient: me.recipients[0] }, vault: VAULT, viewerXOnly: K(0x55) });
  assert.match(v.errors.get("agent"), /not a delegate/);
  const form = km.renderSpendFormHtml({ vault: VAULT, draft: km.spendDraftFrom({ vault: VAULT, viewerXOnly: AGENT }), errors: new Map(), connectedAddress: "kaspa:qa", viewerXOnly: AGENT });
  assert.match(form, /data-kasspend-form=/); assert.match(form, /Payments above/);
});

test("spend BINDING (delegate): the payload must be the reviewed transaction; the delegate signs every input; a stranger / a different signer / an AWAITING request / a tampered payload refuses before the wallet", async () => {
  const { km, api } = mods();
  const below = spendFixture("delegate_spend_below_threshold");
  const req = spendRequest(below);
  const bind = (over = {}) => km.bindKasSpendSigningPayload({ role: "agent", request: req, unsignedSafeJson: below.unsignedSafeJson, signInputs: below.signInputs, network: below.manifest.network.networkId, connectedXOnly: AGENT, ...over });
  assert.equal(bind().ok, true);
  const refuse = (over, code) => assert.throws(() => bind(over), (e) => { assert.equal(e.code, code, e.message); return true; });
  refuse({ connectedXOnly: K(0x55) }, "NOT_THE_SIGNER");
  refuse({ network: "mainnet" }, "NETWORK_MISMATCH");
  refuse({ signInputs: [{ index: 0, sighashType: 1 }].slice(0, 0) }, "PAYLOAD_INVALID");
  const t = JSON.parse(below.unsignedSafeJson); t.outputs[0].value = String(BigInt(t.outputs[0].value) + 1n);
  refuse({ unsignedSafeJson: JSON.stringify(t) }, "PAYLOAD_MISMATCH");
  refuse({ request: { ...req, redeemScripts: {} } }, "REVIEW_REFUSED");
  const above = spendFixture("delegate_spend_above_threshold");
  const aboveReq = spendRequest(above);
  assert.throws(() => km.bindKasSpendSigningPayload({ role: "agent", request: aboveReq, unsignedSafeJson: above.unsignedSafeJson, signInputs: above.signInputs, network: "testnet-10", connectedXOnly: AGENT }), (e) => e.code === "INSUFFICIENT_APPROVALS");
  assert.equal(km.bindKasSpendSigningPayload({ role: "agent", request: { ...aboveReq, state: "BUILT" }, unsignedSafeJson: above.unsignedSafeJson, signInputs: above.signInputs, network: "testnet-10", connectedXOnly: AGENT }).ok, true, "once the approvals are complete the delegate signs");
  api.on(`POST /wallet/v7/requests/${req.requestId}/signature`, () => ({ request: { ...req, state: "SIGNED" } }));
  const adapter = mockAdapter();
  const res = await km.signKasSpend({ request: req, adapter, network: "testnet-10", expectedSignerAddress: "kaspa:qa", connectedXOnly: AGENT });
  assert.equal(res.request.state, "SIGNED"); assert.equal(adapter.calls.length, 1);
  const bad = mockAdapter();
  await assert.rejects(() => km.signKasSpend({ request: req, adapter: bad, network: "testnet-10", expectedSignerAddress: "kaspa:qa", connectedXOnly: K(0x55) }), (e) => e.code === "NOT_THE_SIGNER");
  assert.equal(bad.calls.length, 0);
});

test("spend BINDING (approver): only one of the vault's approvers, only the treasury input, only while AWAITING_APPROVALS, only for an above-threshold payment; the approval is posted with the approver's address", async () => {
  const { km, api } = mods();
  const above = spendFixture("delegate_spend_above_threshold");
  const req = spendRequest(above);
  const entries = [{ index: 0, sighashType: 1 }];
  const bind = (over = {}) => km.bindKasSpendSigningPayload({ role: "approver", request: req, unsignedSafeJson: above.unsignedSafeJson, signInputs: entries, network: "testnet-10", connectedXOnly: APPROVERS[0], ...over });
  assert.equal(bind().ok, true);
  const refuse = (over, code) => assert.throws(() => bind(over), (e) => { assert.equal(e.code, code, e.message); return true; });
  refuse({ connectedXOnly: K(0x55) }, "NOT_AN_APPROVER");
  refuse({ connectedXOnly: AGENT }, "NOT_AN_APPROVER");
  refuse({ signInputs: above.signInputs.length > 1 ? above.signInputs : [{ index: 0, sighashType: 1 }, { index: 0, sighashType: 1 }] }, above.signInputs.length > 1 ? "PAYLOAD_MISMATCH" : "PAYLOAD_INVALID");
  refuse({ request: { ...req, state: "BUILT" } }, "REQUEST_NOT_SIGNABLE");
  const below = spendFixture("delegate_spend_below_threshold");
  assert.throws(() => km.bindKasSpendSigningPayload({ role: "approver", request: spendRequest(below), unsignedSafeJson: below.unsignedSafeJson, signInputs: entries, network: "testnet-10", connectedXOnly: APPROVERS[0] }), (e) => e.code === "NOT_AN_APPROVER");
  api.on(`POST /wallet/v7/requests/${req.requestId}/approvals`, (body) => ({ request: { ...req, approvalProgress: { collected: 1, required: 1 } }, approvals: body }));
  const adapter = mockAdapter(0xcc);
  const res = await km.approveKasSpend({ request: req, adapter, network: "testnet-10", expectedSignerAddress: "kaspa:qappr1", connectedXOnly: APPROVERS[0] });
  assert.equal(res.approvals.approverAddress, "kaspa:qappr1");
  assert.deepEqual(adapter.calls[0].entries, entries, "an approver signs the treasury input only");
  assert.ok(JSON.parse(res.approvals.signedSafeJson).inputs[0].signatureScript.startsWith("41cc"));
});

/* ==================== owner operations of the KAS family as ROOT REQUESTS ==================== */
test("KAS root requests review through org-root-ui's family dispatch (KAS explain layer, redeem-bound); a missing redeem is DO NOT SIGN; the vault-operation summary names the terminal payout", () => {
  const { rootUI } = mods();
  for (const name of ["vault_owner_pause", "vault_emergency_pause", "vault_owner_top_up", "vault_owner_top_up_reserve", "vault_owner_set_approvers", "vault_owner_set_agent_root", "vault_recover"]) {
    const fx = fixture(name);
    const html = rootUI.renderRequestReviewHtml({ manifest: fx.manifest, redeemScripts: fx.redeemScripts });
    assert.match(html, /data-kas-root-review="1"/, name); assert.match(html, /data-org-root-review="verified"/, name); assert.match(html, /EXACT TREASURY OPERATION BEFORE SIGNING/, name);
    const sum = rootUI.vaultOperationSummary({ manifest: fx.manifest, redeemScripts: fx.redeemScripts });
    assert.equal(sum.ok, true, name); assert.ok(sum.lines.length >= 3, name);
    assert.match(rootUI.renderRequestReviewHtml({ manifest: fx.manifest, redeemScripts: {} }), /data-org-root-review="refused"/, `${name} without redeem`);
  }
  const rec = rootUI.vaultOperationSummary({ manifest: fixture("vault_recover").manifest, redeemScripts: fixture("vault_recover").redeemScripts });
  assert.equal(rec.terminal, true); assert.ok(rec.lines.some((l) => /TERMINAL.*105 KAS.*entire balance/.test(l)), rec.lines.join("\n"));
  const appr = rootUI.vaultOperationSummary({ manifest: fixture("vault_owner_set_approvers").manifest, redeemScripts: fixture("vault_owner_set_approvers").redeemScripts });
  assert.ok(appr.lines.some((l) => /Approvers after:/.test(l)));
  const agents = rootUI.vaultOperationSummary({ manifest: fixture("vault_owner_set_agent_root").manifest, redeemScripts: fixture("vault_owner_set_agent_root").redeemScripts });
  assert.ok(agents.lines.some((l) => /New delegate rules/.test(l)));
  const detail = rootUI.renderRequestDetailHtml({ id: "q1", action: "authorize", state: "AUTHORIZED", slots: [], vaultOperations: [{ vaultId: VAULT.vaultId, action: "ownerSetApprovers" }], manifest: fixture("vault_owner_set_approvers").manifest, redeemScripts: fixture("vault_owner_set_approvers").redeemScripts }, { orgRoot: ROOT, viewerXOnly: OWNER });
  assert.match(detail, /Change approvers/);
});

test("KAS root request slot signing binds the owner's payload to the reviewed KAS manifest (family verifier) and the terminal payout = ENTIRE balance to the pinned recovery key", async () => {
  const { rootUI } = mods();
  const fx = fixture("vault_recover");
  const rootInput = Number(fx.rootInputIndex ?? 0);
  const slotEntry = fx.manifest.ownerSet.before.slots.find((sl) => sl.publicKey && sl.publicKey !== SENTINEL);
  const slotPk = slotEntry.publicKey;
  const slotIdx = slotEntry.slot - 1;
  const envelope = { requestVersion: core.orgRootSlotV7.ORG_ROOT_SLOT_REQUEST_VERSION_1, requestId: "d".repeat(32), manifestHash: fx.manifest.manifestHash, txId: fx.manifest.transaction.txId, network: fx.manifest.network.networkId, root: { covenantId: fx.manifest.root.covenantId, outpoint: fx.manifest.root.outpoint, inputIndex: rootInput }, slot: { number: slotEntry.slot, index: slotIdx, publicKey: slotPk }, unsignedSafeJson: fx.unsignedSafeJson, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootInput, sighashType: 1 }] }, expiresAtMs: Date.now() + 100000 };
  const adapter = mockAdapter(0xbb);
  const response = await rootUI.signOwnSlot({ request: { manifest: fx.manifest, redeemScripts: fx.redeemScripts, state: "AUTHORIZED", rootInputIndex: rootInput }, slotEnvelope: envelope, adapter, connectedXOnly: slotPk, network: fx.manifest.network.networkId, expectedSignerAddress: "kaspa:qowner" });
  assert.equal(response.slot.number, slotEntry.slot); assert.equal(response.slot.publicKey, slotPk); assert.equal(response.txId, fx.manifest.transaction.txId); assert.equal(adapter.calls.length, 1);
  const noRedeem = mockAdapter();
  await assert.rejects(() => rootUI.signOwnSlot({ request: { manifest: fx.manifest, redeemScripts: {}, state: "AUTHORIZED", rootInputIndex: rootInput }, slotEnvelope: envelope, adapter: noRedeem, connectedXOnly: slotPk, network: fx.manifest.network.networkId, expectedSignerAddress: "kaspa:qowner" }), (e) => /local verification refused|refus/i.test(e.message));
  assert.equal(noRedeem.calls.length, 0, "R7-04: no redeem, no reconstruction, no wallet");
  const t = JSON.parse(fx.unsignedSafeJson); const payout = t.outputs.findIndex((o) => !o.covenant); if (payout >= 0) t.outputs[payout].value = String(BigInt(t.outputs[payout].value) - 1n);
  const tampered = mockAdapter();
  await assert.rejects(() => rootUI.signOwnSlot({ request: { manifest: fx.manifest, redeemScripts: fx.redeemScripts, state: "AUTHORIZED", rootInputIndex: rootInput }, slotEnvelope: { ...envelope, unsignedSafeJson: JSON.stringify(t) }, adapter: tampered, connectedXOnly: slotPk, network: fx.manifest.network.networkId, expectedSignerAddress: "kaspa:qowner" }), (e) => /differs|mismatch|refus/i.test(e.message));
  assert.equal(tampered.calls.length, 0);
});

test("owner-operation forms of the KAS family: drafts prefilled from the presented state, validation through the core normalizers, the irreversible close needs its typed phrase, every form states the consequence", async () => {
  const { rootUI, km } = mods();
  const agentsDraft = rootUI.vaultOpDraftFrom({ op: "ownerSetAgentRoot", vault: VAULT, currentDaa: "777" });
  assert.equal(agentsDraft.agents.length, VAULT.agents.length); assert.equal(agentsDraft.agents[0].agentKey, AGENT); assert.equal(agentsDraft.agents[0].existing, true);
  let v = await rootUI.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: agentsDraft, vault: VAULT });
  assert.equal(v.ok, true, [...v.errors]); assert.equal(v.vaultOperation.action, "ownerSetAgentRoot"); assert.equal(v.vaultOperation.params.agents.length, VAULT.agents.length);
  assert.equal(v.agentRoot, G.summary.initialState.agentRoot, "an unchanged rule set folds to the installed agent root");
  const apprDraft = rootUI.vaultOpDraftFrom({ op: "ownerSetApprovers", vault: VAULT });
  assert.equal(apprDraft.approvers.length, 2); assert.equal(apprDraft.approvalM, VAULT.approvalM);
  v = await rootUI.validateVaultOpDraft({ op: "ownerSetApprovers", draft: { approvers: [], approvalM: "0" }, vault: VAULT });
  assert.equal(v.ok, false, "pre-sign parity: an existing treasury cannot be changed to zero approvers (vault-transitions-v4 setApproversSuccessorV4)"); assert.match(v.errors.get("approvers"), /zero approvers/);
  v = await rootUI.validateVaultOpDraft({ op: "ownerSetApprovers", draft: { approvers: [{ publicKey: APPROVERS[0], keyMode: true }], approvalM: "1" }, vault: VAULT });
  assert.equal(v.ok, true); assert.deepEqual(v.vaultOperation.params, { approvers: [APPROVERS[0]], approvalM: "1" });
  v = await rootUI.validateVaultOpDraft({ op: "ownerTopUp", draft: { amountKas: "2.5" }, vault: VAULT });
  assert.deepEqual(v.vaultOperation.params, { topUpAmountSompi: "250000000" });
  v = await rootUI.validateVaultOpDraft({ op: "ownerTopUpReserve", draft: { amountKas: "0" }, vault: VAULT });
  assert.equal(v.ok, false);
  v = await rootUI.validateVaultOpDraft({ op: "ownerRecover", draft: { typed: "yes" }, vault: VAULT });
  assert.match(v.errors.get("typed"), /CONFIRM CLOSE TREASURY/);
  v = await rootUI.validateVaultOpDraft({ op: "ownerRecover", draft: { typed: "CONFIRM CLOSE TREASURY" }, vault: VAULT });
  assert.equal(v.ok, true); assert.deepEqual(v.vaultOperation, { vaultId: VAULT.vaultId, action: "ownerRecover", params: {} });
  for (const op of km.VAULT_OP_ORDER) {
    const html = rootUI.renderVaultOpFormHtml({ op, vault: VAULT, orgRoot: ROOT, draft: rootUI.vaultOpDraftFrom({ op, vault: VAULT }), errors: new Map(), connectedAddress: "kaspa:qown1" });
    assert.match(html, /data-vault-profile="policyvault-0.7-kas"/, op);
    const escd = km.vaultOpInfo(op).describe.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    assert.ok(html.includes(escd), `${op} form states its consequence`);
  }
  assert.match(rootUI.renderVaultOpFormHtml({ op: "ownerRecover", vault: VAULT, orgRoot: ROOT, draft: { typed: "" }, errors: new Map(), connectedAddress: "kaspa:qown1" }), /IRREVERSIBLE.*105 KAS/);
  assert.match(rootUI.renderVaultOpFormHtml({ op: "ownerEmergencyPause", vault: VAULT, orgRoot: ROOT, draft: {}, errors: new Map(), connectedAddress: "kaspa:qown1" }), /FROZEN/);
});

test("the KAS module refuses to construct without its core modules and is inert without the setup / payload tools (statement, never a half-wired control)", () => {
  assert.throws(() => kasMod.createModule({ api: fakeApi(), core: { ...core, orgRootKasExplain: undefined }, setup: null, payload: null }), (e) => e.code === "CORE_UNAVAILABLE");
  const km = kasMod.createModule({ api: fakeApi(), core, setup: null, payload: null });
  assert.throws(() => km.renderKasSetupHtml({ draft: km.kasDraftDefaults("kaspa:qx"), step: 0, errors: new Map(), orgRoot: ROOT }), (e) => e.code === "SETUP_UNAVAILABLE");
  assert.throws(() => km.bindKasGenesisSigningPayload({ request: genesisRequest() }), (e) => e.code === "PAYLOAD_TOOLS_UNAVAILABLE");
  assert.equal(kasMod.PROFILE, KAS);
  assert.ok(kasMod.KAS_REFUSAL_CODES.includes("GENERATION_NOT_MAINNET_AUTHORIZED"));
});
