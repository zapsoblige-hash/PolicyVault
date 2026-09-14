#!/usr/bin/env node
"use strict";
/*
 * sdk/tools/gen-v7-kas-explain-fixtures.js — REAL SDK-built v0.7-kas manifests
 * for the pure core / browser tests of core/explain/org-root-kas-explain.js
 * (v0.7 enablement, 2026-09-10). Writes core/explain/test/fixtures/v7-kas-manifests.json:
 *   - org-root-kas manifests (owner operations riding a root transition) with
 *     the vault's predecessor redeem (R7-04 carriage) and the frozen bytes;
 *   - standalone delegate payments (below / above threshold / period
 *     rollover) with the frozen transaction and the predecessor redeem.
 * Deterministic TEST-ONLY keys, synthetic outpoints, no chain. Requires the
 * vendored silverc + pv_call_encoder (REQUIREMENT_NOT_AVAILABLE otherwise).
 *
 * Usage: node sdk/tools/gen-v7-kas-explain-fixtures.js [OUT=<path>]
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { loadConfig } = require("../src/config");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { buildV7KasTransaction, buildCreateV7KasVault, createApprovalPackageForBuildV7Kas } = require("../src/vault-builders-v7-kas");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { sompiToKas } = require("../src/amounts");
const { registryEntryToJson, normalizeRegistry } = require("../src/manifest-v4");
const { buildOrgRootIntentManifestV7Kas, buildRootedKasVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7-kas");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");

const outArg = process.argv.find((a) => a.startsWith("OUT="));
const OUT = outArg ? outArg.slice(4) : path.join(__dirname, "..", "..", "core", "explain", "test", "fixtures", "v7-kas-manifests.json");
const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-fix-")) });
if (!fs.existsSync(config.silvercPath)) { console.error("REQUIREMENT_NOT_AVAILABLE: vendored silverc not staged"); process.exit(2); }

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7), ROOT_ID = H(0x52), VAULT_COV_ID = H(0x44), FUEL = H(0x64), RECOVERY_PK = H(0x51), AGENT_PK = H(0x62), RECIPIENT_PK = H(0x63), ROOT_KAS = 3n * KAS;
const slots = (keys) => { const out = []; for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY); return out; };
const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const ownerSet = { owners: slots([H(0x71), H(0x72), H(0x73)]), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const rootState = { boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0 };
const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: ROOT_ID });
const vaultTemplate = { vaultId: H(0x44), ...rootPins, recoveryPk: RECOVERY_PK };
const rTree = buildRecipientTree([RECIPIENT_PK]);
const policy = { agentPk: AGENT_PK, maxPerSpend: (5n * KAS).toString(), periodBudget: (20n * KAS).toString(), periodLengthDaa: "1000", periodStartDaa: "5000", periodSpent: "0", approvalThreshold: (2n * KAS).toString(), agentMaxFeePerTx: (KAS / 10n).toString(), agentRecipientRoot: rTree.root };
const tree = buildAgentTreeV4([policy]);
const state = (over = {}) => ({ protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: tree.root, approvers: [H(0x91), H(0x92)], approvalM: "1", policyNonce: "0", ...over });
const value = (s) => (BigInt(s.protectedValue) + BigInt(s.feeReserve)).toString();
const chain = (s, withRoot = true) => ({
  predecessorOutpoint: { transactionId: H(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: value(s),
  fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (50n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
  ...(withRoot ? { root: { template: rootTemplate, state: rootState, outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() } } : {})
});
const build = (action, params = {}, stateOver = {}, withRoot = true, fuel = true) => {
  const s = state(stateOver);
  const c = chain(s, withRoot);
  if (!fuel) delete c.fuel;
  return buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: s, action, params, chain: c, changeXOnly: FUEL });
};
const orgFixture = (name, b, satisfied) => {
  const manifest = buildOrgRootIntentManifestV7Kas({ build: b, vaultOperations: [{ build: b }], satisfiedApprovals: satisfied });
  const wtx = frozenToWasmTransaction(config, b.frozen); wtx.finalize();
  const rootInputIndex = b.frozen.inputs.findIndex((i) => i.utxo.covenantId === ROOT_ID);
  return { name, kind: "org-root-kas", manifest, redeemScripts: { [b.covenantId]: b.vaultRedeemScriptHex }, frozenCanonicalJson: b.frozenCanonicalJson, txId: b.txId, unsignedSafeJson: wtx.serializeToSafeJSON(), rootInputIndex, signInputs: b.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) };
};
const spendFixture = (name, b, approvalPackage = null) => {
  const manifest = buildRootedKasVaultManifestV7({ build: b, approvalPackage });
  const wtx = frozenToWasmTransaction(config, b.frozen); wtx.finalize();
  return { name, kind: "rooted-kas-spend", manifest, frozenCanonicalJson: b.frozenCanonicalJson, redeemHex: b.vaultRedeemScriptHex, txId: b.txId, aboveThreshold: b.aboveThreshold === true, unsignedSafeJson: wtx.serializeToSafeJSON(), signInputs: b.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })), covenantInputIndex: 0, redeemScripts: { [b.covenantId]: b.vaultRedeemScriptHex } };
};
const newPolicy = { ...policy, agentPk: H(0x66), maxPerSpend: (2n * KAS).toString(), recipients: [RECIPIENT_PK] };
const manifests = [
  orgFixture("vault_owner_pause", build("ownerPause"), 2),
  orgFixture("vault_emergency_pause", build("ownerEmergencyPause"), 1),
  orgFixture("vault_owner_top_up", build("ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() }), 2),
  orgFixture("vault_owner_top_up_reserve", build("ownerTopUpReserve", { topUpReserveAmountSompi: (2n * KAS).toString() }), 2),
  orgFixture("vault_owner_set_approvers", build("ownerSetApprovers", { approvers: [H(0x93)], approvalM: "1" }), 2),
  orgFixture("vault_owner_set_agent_root", build("ownerSetAgentRoot", { agents: [newPolicy] }), 2),
  orgFixture("vault_recover", build("ownerRecover"), 2)
];
const below = build("agentSpend", { payAmountSompi: (1n * KAS).toString(), agentPk: AGENT_PK, agents: [policy], recipient: RECIPIENT_PK, recipients: [RECIPIENT_PK] }, {}, false, false);
const above = build("agentSpend", { payAmountSompi: (3n * KAS).toString(), agentPk: AGENT_PK, agents: [policy], recipient: RECIPIENT_PK, recipients: [RECIPIENT_PK] }, {}, false, false);
const spentLeaf = { ...policy, periodSpent: (18n * KAS).toString() };
const rolloverTree = buildAgentTreeV4([spentLeaf]);
const rollover = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state({ agentRoot: rolloverTree.root }), action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: AGENT_PK, agents: [spentLeaf], recipient: RECIPIENT_PK, recipients: [RECIPIENT_PK], periodsElapsed: "1" }, chain: (() => { const c = chain(state({ agentRoot: rolloverTree.root }), false); delete c.fuel; return c; })(), changeXOnly: FUEL });
const spends = [
  spendFixture("delegate_spend_below_threshold", below),
  spendFixture("delegate_spend_above_threshold", above, createApprovalPackageForBuildV7Kas(above)),
  spendFixture("delegate_spend_period_rollover", rollover)
];
/* a KAS vault GENESIS the way the server presents it (summary + wallet payload) — the browser rebuilds the vault script from these rules */
const FUNDER = H(0x0f);
const genesisState = state();
const genesis = buildCreateV7KasVault({ config, templateInput: vaultTemplate, initialStateInput: genesisState, funding: [{ outpoint: { transactionId: H(0x05), index: 0 }, amount: (200n * KAS).toString(), scriptPublicKeyHex: `20${FUNDER}ac` }], changeXOnly: FUNDER });
const gwtx = frozenToWasmTransaction(config, genesis.frozen); gwtx.finalize();
const initialRegistry = normalizeRegistry([{ ...policy, recipients: [RECIPIENT_PK] }]).entries.map(registryEntryToJson);
const genesisSummary = { kind: "genesis-summary", contractVersion: "policyvault-0.7-kas", networkId: config.networkId, vaultId: vaultTemplate.vaultId, covenantId: genesis.covenantId, orgRootCovenantId: ROOT_ID, template: genesis.template, initialState: genesis.initialState, agents: initialRegistry, approvers: [H(0x91), H(0x92)], approvalM: "1", recoveryPk: RECOVERY_PK, depositKas: sompiToKas(BigInt(genesisState.protectedValue)), feeReserveKas: sompiToKas(BigInt(genesisState.feeReserve)), txId: genesis.txId, requiredFeeSompi: genesis.requiredFeeSompi };
const genesisFixture = { name: "kas_vault_genesis", kind: "kas-genesis", funderXOnly: FUNDER, summary: genesisSummary, unsignedSafeJson: gwtx.serializeToSafeJSON(), signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })), frozenCanonicalJson: genesis.frozenCanonicalJson, vaultOutputIndex: genesis.vaultOutputIndex, vaultScriptHex: genesis.vaultScriptHex, scriptSha256: genesis.scriptSha256, txId: genesis.txId, requiredFeeSompi: genesis.requiredFeeSompi };
const doc = { schema: "policyvault-v7-kas-explain-fixtures/1", genesis: genesisFixture, generatedBy: "sdk/tools/gen-v7-kas-explain-fixtures.js", covenant: "policyvault-0.7-kas (CANDIDATE)", vaultTemplate, rootTemplate, manifests, spends };
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(doc, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 1) + "\n");
console.log(`wrote ${OUT}: ${manifests.length} org-root-kas manifests + ${spends.length} delegate payments`);
