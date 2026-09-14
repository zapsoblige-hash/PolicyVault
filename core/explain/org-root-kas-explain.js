"use strict";

/*
 * PolicyVault v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT — SIGNER-VISIBLE
 * EXPLANATIONS (v1). v0.7 mainnet-enablement directive (2026-09-10):
 * "threshold ownership, approvals, funding/reserves, fees, delays,
 * emergency, irreversible recovery explained before signing".
 *
 * Two manifest families, two entry points, ONE discipline (the sibling of
 * core/explain/org-root-explain.js, whose fixed root narration this module
 * reuses verbatim from its exported tables):
 *
 *   structured({ manifest, redeemScripts })
 *     policyvault-org-root-kas-manifest/1  — an OWNER OPERATION on a KAS
 *     vault riding a root transition (or a root-only action described by
 *     the KAS family). Independently re-verified through
 *     verifyOrgRootIntentManifestV7Kas with the vault's predecessor redeem
 *     (R7-04: the declared pins and the successor script are bound to the
 *     spent vault). Rendered as an owner approval screen.
 *
 *   structuredSpend({ manifest, frozen, redeemHex })
 *     policyvault-rooted-kas-vault-manifest/1 (action agentSpend) — a
 *     DELEGATE PAYMENT that never touches the root. Independently
 *     re-verified through verifyRootedKasVaultManifestV7 against the frozen
 *     transaction bytes with the predecessor redeem bound. Rendered for the
 *     paying delegate and for every vault-level approver who co-signs above
 *     the delegate's threshold. A standalone OWNER operation is refused
 *     (VERIFY_WITHIN_PARENT — its authority is the root input).
 *
 * WHAT THIS LAYER SHOWS for the KAS profile, beyond the root narration:
 *   - OWNERSHIP: the vault has no owner key; the organization's root quorum
 *     owns it (fixed sentence);
 *   - FUNDS: protected principal and fee reserve before/after, the exact
 *     network fee and which pool pays it, external funding of a top-up;
 *   - APPROVALS: the vault-level approver slots and M — a SEPARATE tier from
 *     the root's quorum — and, for a spend above the delegate's threshold,
 *     how many approvals are required;
 *   - DELEGATE RULES: every installed policy (cap, budget, period, spent,
 *     threshold, fee cap, recipients) when the owners replace them;
 *   - EMERGENCY: the lighter emergency quorum and what it can and cannot do;
 *   - IRREVERSIBLE RECOVERY: a terminal close pays the ENTIRE balance to the
 *     genesis-pinned recovery key, in full, nowhere else;
 *   - DELAYS: a period rollover's lock time; the root's idle delays (from the
 *     root narration).
 *
 * BINDING RULES (fail closed, no default route): no caller-supplied verdict;
 * every non-verified manifest renders a prominent DO-NOT-SIGN refusal naming
 * every failing check; unknown versions refuse; no truncation of keys, ids,
 * outpoints or amounts; every amount through core/explain/kas.js (BigInt
 * only). Both entry points are TOTAL (never throw). Portable shared core.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/explain/test/org-root-kas-explain.test.js
 * over real SDK-built fixtures; sdk/test/kas-explain.test.js on fresh builds).
 * Explanations RENDER; they never authorize.
 */

const {
  ORG_ROOT_KAS_MANIFEST_VERSION_1,
  ROOTED_KAS_VAULT_MANIFEST_VERSION_1,
  verifyOrgRootIntentManifestV7Kas,
  verifyRootedKasVaultManifestV7
} = require("../intent/org-root-manifest-v7-kas");
const { ORG_ROOT_MANIFEST_VERSION_1 } = require("../intent/org-root-manifest-v7");
const { EXPLANATION_VERDICTS, ROOT_OUTPOINT_KILL_SWITCH_LINE, ACTION_SUMMARY, WARNING_TEXT } = require("./org-root-explain");
const { kasAmount } = require("./kas");

const ORG_ROOT_KAS_EXPLANATION_VERSION_1 = "policyvault-org-root-kas-explanation/1";
const KAS_SPEND_EXPLANATION_VERSION_1 = "policyvault-rooted-kas-spend-explanation/1";
const APPROVER_SENTINEL = "00".repeat(32);

/* Fixed sentences — the text depends only on the action, never on the caller. */
const KAS_OWNERSHIP_STATEMENT =
  "OWNERSHIP: this vault has NO owner key. It is owned by the organization's on-chain root: every owner operation needs the root's owner quorum (M of N), enforced by the Kaspa covenant. Delegates may pay only within their installed rules; a payment above a delegate's threshold also needs M of this vault's own approvers — a separate tier from the root's quorum.";
const KAS_VAULT_ACTION_SUMMARY = Object.freeze({
  ownerSetAgentRoot: "Replace this vault's delegate (agent) rules — every delegate, its cap per payment, its budget per period, its approval threshold, its network-fee cap and its allowed recipients.",
  ownerSetApprovers: "Replace this vault's approver set and the number of approvals (M) a payment above a delegate's threshold needs.",
  ownerTopUp: "Add KAS to this vault's PROTECTED PRINCIPAL — the funds delegates may pay out under their rules.",
  ownerTopUpReserve: "Add KAS to this vault's FEE RESERVE — the pool that pays the network fee of each delegate payment.",
  ownerPause: "Pause this vault — delegate payments stop until the owners unpause it. Nothing moves.",
  ownerUnpause: "Unpause this vault — delegate payments resume under the existing rules and remaining budgets.",
  ownerEmergencyPause: "EMERGENCY-pause this vault on the lighter emergency quorum — delegate payments stop. The root is frozen by the same transaction.",
  ownerRecover: "CLOSE this vault and pay its ENTIRE balance (protected principal + fee reserve) to the recovery key pinned when the vault was created. This is terminal and cannot be undone.",
  agentSpend: "A delegate (agent) payment of native KAS under this vault's installed rules."
});
const KAS_WARNING_TEXT = Object.freeze({
  TERMINAL_KAS_VAULT_OPERATION:
    "A vault is CLOSED by this transaction. Its ENTIRE balance — protected principal AND fee reserve — pays to the recovery key pinned when that vault was created; this destination cannot be changed by this transaction or by anyone. There is no undo.",
  APPROVER_SET_CHANGES: "The vault's APPROVER set or its required approvals (M) CHANGE in this transaction. Check every key below against your own records.",
  DELEGATE_RULES_REPLACED: "The vault's delegate rules are REPLACED completely by the set listed below. Any delegate not listed can no longer pay from this vault.",
  PRINCIPAL_FUNDED: "This transaction adds KAS to the vault's protected principal from the fee payer's own funds.",
  RESERVE_FUNDED: "This transaction adds KAS to the vault's fee reserve from the fee payer's own funds.",
  ABOVE_THRESHOLD: "This payment is ABOVE the delegate's approval threshold: the listed number of vault-level approvers must co-sign the SAME transaction before the delegate's signature is accepted by the covenant.",
  PERIOD_ROLLOVER: "This payment starts a NEW budget period: it carries a LOCK TIME and is only valid once the chain's DAA score reaches the new period start. Until then it cannot confirm.",
  RESERVE_PAYS_FEE: "The network fee is paid from the vault's fee reserve, not by the delegate.",
  FUEL_PAYS_FEE: "The network fee is paid by an ordinary input of the delegate's wallet (the vault's reserve is not consumed for it)."
});

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}
function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
function sanitizeDetail(value) {
  return String(value == null ? "" : value).replace(/[\r\n\t]+/g, " ").replace(/[^\x20-\x7e]/g, "?").slice(0, 400);
}
function outpointText(op) {
  return op && typeof op === "object" ? `${op.transactionId}:${op.index}` : "(none)";
}
function warning(code) {
  const detail = Object.prototype.hasOwnProperty.call(KAS_WARNING_TEXT, code) ? KAS_WARNING_TEXT[code] : WARNING_TEXT[code];
  return { code, detail };
}
function activeSlots(slots) {
  return Array.isArray(slots) ? slots.filter((k) => typeof k === "string" && k !== APPROVER_SENTINEL) : [];
}
function baseDocument(version) {
  return {
    explanationVersion: version,
    verdict: null,
    statement: null,
    refusal: null,
    context: null,
    manifestHash: null,
    txId: null,
    network: null,
    ownership: null,
    organization: null,
    authorization: null,
    quorum: null,
    ownerSet: null,
    rootState: null,
    timeLock: null,
    freshness: null,
    fee: null,
    vaultOperations: null,
    spend: null,
    warnings: null,
    verification: null
  };
}
function refusalDocument(version, { reason, failures, context = null, manifestHash = null, txId = null, verification = null }) {
  const names = [...new Set(failures.map((f) => f.name))].sort();
  const doc = baseDocument(version);
  doc.verdict = EXPLANATION_VERDICTS.REFUSED;
  doc.refusal = { reason: String(reason), failingChecks: names, failures: failures.map((f) => ({ name: String(f.name), detail: f.detail == null ? null : String(f.detail) })) };
  doc.context = context;
  doc.manifestHash = manifestHash;
  doc.txId = txId;
  doc.verification = verification;
  return deepFreeze(doc);
}
function refusalContext(manifest) {
  if (!isPlainObject(manifest)) return null;
  const ctx = { unverified: true, manifestVersion: null, actionName: null, networkId: null, rootCovenantId: null, vaultId: null };
  if (typeof manifest.manifestVersion === "string") ctx.manifestVersion = manifest.manifestVersion;
  if (isPlainObject(manifest.action)) ctx.actionName = typeof manifest.action.name === "string" ? manifest.action.name : typeof manifest.action.sdkAction === "string" ? manifest.action.sdkAction : null;
  if (isPlainObject(manifest.network) && typeof manifest.network.networkId === "string") ctx.networkId = manifest.network.networkId;
  if (isPlainObject(manifest.root) && typeof manifest.root.covenantId === "string") ctx.rootCovenantId = manifest.root.covenantId;
  if (isPlainObject(manifest.vault) && typeof manifest.vault.vaultId === "string") ctx.vaultId = manifest.vault.vaultId;
  return ctx;
}

/* ---- the KAS vault's own amounts + policies ---- */
function kasPolicyDocument(p, label) {
  return {
    agentPk: p.agentPk,
    maxPerSpend: kasAmount(p.maxPerSpend, `${label}.maxPerSpend`),
    periodBudget: kasAmount(p.periodBudget, `${label}.periodBudget`),
    periodSpent: kasAmount(p.periodSpent, `${label}.periodSpent`),
    periodLengthDaa: String(p.periodLengthDaa),
    periodStartDaa: String(p.periodStartDaa),
    approvalThreshold: kasAmount(p.approvalThreshold, `${label}.approvalThreshold`),
    agentMaxFeePerTx: kasAmount(p.agentMaxFeePerTx, `${label}.agentMaxFeePerTx`),
    agentRecipientRoot: p.agentRecipientRoot,
    recipients: Array.isArray(p.recipients) ? p.recipients.map((r) => String(r)) : null
  };
}
function policyLines(p, indent) {
  const lines = [];
  lines.push(`${indent}delegate ${p.agentPk}: up to ${p.maxPerSpend.kas} KAS per payment, ${p.periodBudget.kas} KAS per ${p.periodLengthDaa} DAA (period starts ${p.periodStartDaa}, spent so far ${p.periodSpent.kas} KAS), payments above ${p.approvalThreshold.kas} KAS need the vault's approvers, network fee per payment at most ${p.agentMaxFeePerTx.kas} KAS.`);
  if (p.recipients !== null) lines.push(`${indent}  may pay ONLY these ${p.recipients.length} recipient(s): ${p.recipients.join(", ")}`);
  return lines;
}
function vaultOperationDocument(op) {
  const m = op.manifest;
  const a = m.action;
  const k = m.accounting.kas;
  const before = m.stateBefore ? m.stateBefore.state : null;
  const after = m.stateAfter ? m.stateAfter.state : null;
  const tier = (s) => (s ? { approvers: activeSlots(s.approverSlots), approvalM: String(s.approvalM) } : null);
  return {
    covenantId: op.covenantId,
    vaultId: op.vaultId,
    sdkAction: a.sdkAction,
    summary: KAS_VAULT_ACTION_SUMMARY[a.sdkAction] ?? null,
    role: a.role,
    terminal: a.terminal,
    mutationClass: a.mutationClass,
    opSelector: a.opSelector,
    requiresRootInput: a.requiresRootInput,
    requiredRootAction: a.requiredRootAction,
    expectFrozenAfter: a.expectFrozenAfter,
    orgRootCovenantId: m.vault.orgRootCovenantId,
    recoveryPk: m.vault.recoveryPk,
    kas: {
      protectedBefore: kasAmount(k.predecessorProtected, "vault.predecessorProtected"),
      protectedAfter: kasAmount(k.successorProtected, "vault.successorProtected"),
      feeReserveBefore: kasAmount(k.predecessorFeeReserve, "vault.predecessorFeeReserve"),
      feeReserveAfter: kasAmount(k.successorFeeReserve, "vault.successorFeeReserve"),
      totalBefore: kasAmount(BigInt(k.predecessorProtected) + BigInt(k.predecessorFeeReserve), "vault.totalBefore"),
      totalAfter: kasAmount(k.successorTotal, "vault.successorTotal"),
      reserveConsumed: kasAmount(k.reserveConsumed, "vault.reserveConsumed"),
      externalFunding: kasAmount(k.externalFunding, "vault.externalFunding"),
      fee: kasAmount(k.fee, "vault.fee"),
      terminalPayout: kasAmount(k.terminalPayout, "vault.terminalPayout")
    },
    paused: before && after ? { before: String(before.paused), after: String(after.paused) } : before ? { before: String(before.paused), after: null } : null,
    approverTier: { before: tier(before), after: tier(after) },
    stateBefore: m.stateBefore ? { stateId: m.stateBefore.stateId, outpoint: m.stateBefore.outpoint } : null,
    stateAfter: m.stateAfter ? { stateId: m.stateAfter.stateId } : null,
    policyNonce: before && after ? { before: String(before.policyNonce), after: String(after.policyNonce) } : null,
    agentSet: a.sdkAction === "ownerSetAgentRoot" && m.policy && Array.isArray(m.policy.agentSet) ? m.policy.agentSet.map((p) => kasPolicyDocument(p, "agentSet")) : null,
    manifestHash: m.manifestHash
  };
}
function vaultOperationLines(v, index) {
  const lines = [];
  lines.push(`Vault operation ${index}: ${v.sdkAction} on KAS vault ${v.vaultId} (covenant ${v.covenantId}).`);
  if (v.summary !== null) lines.push(`  ${v.summary}`);
  lines.push(`  Authority: ${v.mutationClass}; this operation requires the root to run ${v.requiredRootAction === null ? "no root action" : v.requiredRootAction}.`);
  lines.push(`  This vault is pinned to root covenant ${v.orgRootCovenantId}.`);
  lines.push(`  Protected principal: ${v.kas.protectedBefore.kas} KAS -> ${v.kas.protectedAfter.kas} KAS. Fee reserve: ${v.kas.feeReserveBefore.kas} KAS -> ${v.kas.feeReserveAfter.kas} KAS.`);
  if (v.kas.externalFunding.sompi !== "0") lines.push(`  Funded from the fee payer's wallet: ${v.kas.externalFunding.kas} KAS.`);
  lines.push(`  Network fee of this transaction: ${v.kas.fee.kas} KAS, paid by the fee payer (the vault's reserve is consumed: ${v.kas.reserveConsumed.kas} KAS).`);
  if (v.approverTier.before) {
    const b = v.approverTier.before;
    lines.push(`  Approver tier before: ${b.approvalM} of ${b.approvers.length} approver(s)${b.approvers.length ? `: ${b.approvers.join(", ")}` : " (no approvers — every payment within a delegate's rules needs no approval)"}.`);
  }
  if (v.approverTier.after && v.sdkAction === "ownerSetApprovers") {
    const af = v.approverTier.after;
    lines.push(`  Approver tier AFTER: ${af.approvalM} of ${af.approvers.length} approver(s)${af.approvers.length ? `: ${af.approvers.join(", ")}` : " (none)"}.`);
  }
  if (v.paused && v.paused.after !== null) lines.push(`  Paused: ${v.paused.before} -> ${v.paused.after}.`);
  if (v.terminal) lines.push(`  TERMINAL: this vault is CLOSED. Payout ${v.kas.terminalPayout.kas} KAS (its ENTIRE balance) to the genesis-pinned recovery key ${v.recoveryPk}. Irreversible.`);
  if (v.agentSet !== null) {
    if (v.agentSet.length === 0) lines.push("  New delegate rules: EMPTY — after this operation no delegate can pay from this vault until a new set is installed.");
    else lines.push(`  New delegate rules (${v.agentSet.length} ${v.agentSet.length === 1 ? "policy" : "policies"}) — these are the RULES being installed; the successor agentRoot is their Merkle root:`);
    for (const p of v.agentSet) for (const l of policyLines(p, "    ")) lines.push(l);
  }
  if (v.policyNonce !== null) lines.push(`  Vault policy nonce advances ${v.policyNonce.before} -> ${v.policyNonce.after}.`);
  return lines;
}

/* ------------------------------------------------------------------ */
/* structured() — the org-root-KAS manifest (owner operations)          */
/* ------------------------------------------------------------------ */

function structured(input) {
  const V = ORG_ROOT_KAS_EXPLANATION_VERSION_1;
  const { manifest, redeemScripts } = input && typeof input === "object" ? input : {};
  try {
    if (!isPlainObject(manifest)) return refusalDocument(V, { reason: "No organizational-root manifest was supplied — failing closed.", failures: [{ name: "manifestSupplied", detail: "an org-root-kas manifest object is required" }] });
    if (manifest.manifestVersion === ROOTED_KAS_VAULT_MANIFEST_VERSION_1) {
      const sdkAction = isPlainObject(manifest.action) ? manifest.action.sdkAction : null;
      return refusalDocument(V, {
        reason: sdkAction === "agentSpend"
          ? "A delegate payment is explained through structuredSpend({ manifest, frozen, redeemHex }) — it needs the frozen transaction and the predecessor redeem to verify."
          : "A rooted-vault owner operation is never explained on its own: its authority IS the organizational root input. Supply the parent org-root-kas manifest.",
        failures: [{ name: "verifyWithinParent", detail: `${ROOTED_KAS_VAULT_MANIFEST_VERSION_1} ${sdkAction === "agentSpend" ? "delegate payments use structuredSpend" : `owner operations are explained inside ${ORG_ROOT_KAS_MANIFEST_VERSION_1}`}` }],
        context: refusalContext(manifest),
        manifestHash: typeof manifest.manifestHash === "string" ? manifest.manifestHash : null
      });
    }
    if (manifest.manifestVersion !== ORG_ROOT_KAS_MANIFEST_VERSION_1) {
      return refusalDocument(V, {
        reason: manifest.manifestVersion === ORG_ROOT_MANIFEST_VERSION_1 ? "This is a rooted TOKEN-vault (payment profile) manifest — explain it through core/explain/org-root-explain.js." : "Unknown manifest version — failing closed (no default route).",
        failures: [{ name: "manifestVersion", detail: `expected ${ORG_ROOT_KAS_MANIFEST_VERSION_1}, got ${JSON.stringify(manifest.manifestVersion)}` }],
        context: refusalContext(manifest)
      });
    }
    const verification = verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts: isPlainObject(redeemScripts) ? redeemScripts : {} });
    const verificationSummary = { verdict: verification.verdict, checks: verification.checks.map((c) => ({ name: c.name, ok: c.ok })), failingChecks: [...new Set(verification.failures.map((f) => f.name))].sort() };
    if (verification.verdict !== "VERIFIED") {
      return refusalDocument(V, {
        reason: "This organizational-root approval FAILED local verification against the frozen transaction it describes and must not be signed.",
        failures: verification.failures.map((f) => ({ name: f.name, detail: f.detail })),
        context: refusalContext(manifest),
        manifestHash: manifest.manifestHash ?? null,
        txId: manifest.transaction && typeof manifest.transaction.txId === "string" ? manifest.transaction.txId : null,
        verification: verificationSummary
      });
    }
    const doc = baseDocument(V);
    const a = manifest.action;
    const before = manifest.ownerSet.before;
    const after = manifest.ownerSet.after;
    const changes = manifest.ownerSet.changes;
    doc.verdict = EXPLANATION_VERDICTS.VERIFIED_EXACT;
    doc.statement = verification.statement;
    doc.manifestHash = manifest.manifestHash;
    doc.txId = manifest.transaction.txId;
    doc.network = { networkId: manifest.network.networkId };
    doc.ownership = { statement: KAS_OWNERSHIP_STATEMENT, profile: "policyvault-0.7-kas", candidate: true };
    doc.organization = {
      orgId: manifest.root.orgId,
      rootCovenantId: manifest.root.covenantId,
      rootOutpoint: { transactionId: manifest.root.outpoint.transactionId, index: manifest.root.outpoint.index },
      contractVersion: manifest.root.contractVersion,
      recoveryEnabled: BigInt(before.recoveryM) > 0n,
      successionEnabled: manifest.root.template.successionEnabled === true,
      successorPk: manifest.root.template.successorPk,
      recoveryDelayDaa: manifest.root.template.recoveryDelayDaa,
      successionDelayDaa: manifest.root.template.successionDelayDaa
    };
    doc.authorization = { actionName: a.name, actionCode: a.code === null ? null : String(a.code), entrypoint: a.entrypoint, authorityClass: a.authorityClass, authorityClassForPreviousSet: a.authorityClassForPreviousSet, summary: ACTION_SUMMARY[a.name] ?? null };
    const required = BigInt(a.requiredApprovals);
    const satisfied = a.satisfiedApprovals === null ? null : BigInt(a.satisfiedApprovals);
    doc.quorum = { quorumSource: a.quorumSource, requiredApprovals: required.toString(), satisfiedApprovals: satisfied === null ? null : satisfied.toString(), quorumSatisfied: satisfied === null ? null : satisfied >= required, activeOwnerSlots: String(before.activeCount), ownerM: before.ownerM, emergencyK: before.emergencyK, recoveryM: before.recoveryM, expectedSignerSlots: a.expectedSignerSlots.map((s) => ({ slot: s.slot, publicKey: s.publicKey })) };
    doc.ownerSet = {
      before: { activeCount: String(before.activeCount), ownerM: before.ownerM, emergencyK: before.emergencyK, recoveryM: before.recoveryM, slots: before.slots.map((s) => ({ slot: s.slot, publicKey: s.publicKey })) },
      after: { activeCount: String(after.activeCount), ownerM: after.ownerM, emergencyK: after.emergencyK, recoveryM: after.recoveryM, slots: after.slots.map((s) => ({ slot: s.slot, publicKey: s.publicKey })) },
      added: changes.added.slice(),
      removed: changes.removed.slice(),
      thresholdsChanged: changes.thresholdsChanged === true,
      frozenChanged: changes.frozenChanged === true
    };
    doc.rootState = { beforeDigest: manifest.rootState.before.digest, afterDigest: manifest.rootState.after.digest, successorTailHex: manifest.rootState.after.tailHex, frozenBefore: String(manifest.rootState.before.state.frozen), frozenAfter: String(manifest.rootState.after.state.frozen), nonceBefore: String(manifest.rootState.before.state.rootNonce), nonceAfter: String(manifest.rootState.after.state.rootNonce) };
    const minSequence = BigInt(a.minSequence);
    doc.timeLock = minSequence > 0n ? { kind: "RELATIVE_INPUT_AGE", minSequence: minSequence.toString(), delayDaa: a.name === "succession" ? manifest.root.template.successionDelayDaa : manifest.root.template.recoveryDelayDaa, resetByAnyRootTransaction: true } : null;
    doc.freshness = { kind: manifest.freshness.kind, rootOutpoint: { transactionId: manifest.freshness.rootOutpoint.transactionId, index: manifest.freshness.rootOutpoint.index }, expiry: null, statement: ROOT_OUTPOINT_KILL_SWITCH_LINE };
    doc.fee = { networkFee: kasAmount(manifest.fee.requiredFeeSompi, "fee.requiredFeeSompi"), rootMaxFeePerTx: kasAmount(manifest.fee.rootMaxFeePerTx, "fee.rootMaxFeePerTx"), rootValueLoss: kasAmount(manifest.fee.rootValueLoss, "fee.rootValueLoss"), rootValueBefore: kasAmount(manifest.root.valueBefore, "root.valueBefore"), rootValueAfter: kasAmount(manifest.root.valueAfter, "root.valueAfter") };
    doc.vaultOperations = manifest.vaultOperations.map((op) => vaultOperationDocument(op));
    const warnings = [];
    if (a.authorityClass === "AUTHORITY-EXPANDING") warnings.push(warning("AUTHORITY_EXPANDING"));
    if (a.authorityClass === "AUTHORITY-REDUCING") warnings.push(warning("AUTHORITY_REDUCING"));
    if (a.quorumSource === "emergencyK") warnings.push(warning("EMERGENCY_QUORUM"));
    if (a.name === "ownerRecover") warnings.push(warning("RECOVERY_INSTALLS_NEW_SET"));
    if (a.authorityClassForPreviousSet === "TERMINAL") warnings.push(warning("SUCCESSION_TERMINAL_FOR_PREVIOUS_SET"));
    if (doc.rootState.frozenAfter === "1") warnings.push(warning("LANDS_FROZEN"));
    if (doc.timeLock !== null) warnings.push(warning("RELATIVE_AGE_GATE"));
    if (doc.ownerSet.added.length > 0 || doc.ownerSet.removed.length > 0) warnings.push(warning("OWNER_SET_CHANGES"));
    if (doc.ownerSet.thresholdsChanged) warnings.push(warning("THRESHOLDS_CHANGE"));
    if (!doc.organization.recoveryEnabled) warnings.push(warning("RECOVERY_DISABLED"));
    if (!doc.organization.successionEnabled) warnings.push(warning("SUCCESSION_DISABLED"));
    if (doc.vaultOperations.some((v) => v.terminal)) warnings.push(warning("TERMINAL_KAS_VAULT_OPERATION"));
    if (doc.vaultOperations.some((v) => v.sdkAction === "ownerSetApprovers")) warnings.push(warning("APPROVER_SET_CHANGES"));
    if (doc.vaultOperations.some((v) => v.sdkAction === "ownerSetAgentRoot")) warnings.push(warning("DELEGATE_RULES_REPLACED"));
    if (doc.vaultOperations.some((v) => v.sdkAction === "ownerTopUp")) warnings.push(warning("PRINCIPAL_FUNDED"));
    if (doc.vaultOperations.some((v) => v.sdkAction === "ownerTopUpReserve")) warnings.push(warning("RESERVE_FUNDED"));
    if (doc.quorum.satisfiedApprovals === null) warnings.push(warning("APPROVALS_NOT_YET_COUNTED"));
    if (BigInt(manifest.fee.rootValueLoss) > 0n) warnings.push(warning("ROOT_VALUE_LOSS"));
    doc.warnings = warnings;
    doc.verification = verificationSummary;
    return deepFreeze(doc);
  } catch (e) {
    return refusalDocument(V, { reason: "The explanation engine failed internally — failing closed.", failures: [{ name: "explainInternal", detail: `${e && e.message ? e.message : String(e)}` }] });
  }
}

/* ------------------------------------------------------------------ */
/* structuredSpend() — a standalone delegate payment (agentSpend)       */
/* ------------------------------------------------------------------ */

function structuredSpend(input) {
  const V = KAS_SPEND_EXPLANATION_VERSION_1;
  const { manifest, frozen, redeemHex } = input && typeof input === "object" ? input : {};
  try {
    if (!isPlainObject(manifest)) return refusalDocument(V, { reason: "No delegate-payment manifest was supplied — failing closed.", failures: [{ name: "manifestSupplied", detail: "a rooted-kas-vault manifest object is required" }] });
    if (manifest.manifestVersion !== ROOTED_KAS_VAULT_MANIFEST_VERSION_1) {
      return refusalDocument(V, { reason: "Unknown manifest version for a delegate payment — failing closed (no default route).", failures: [{ name: "manifestVersion", detail: `expected ${ROOTED_KAS_VAULT_MANIFEST_VERSION_1}, got ${JSON.stringify(manifest.manifestVersion)}` }], context: refusalContext(manifest) });
    }
    if (!isPlainObject(manifest.action) || manifest.action.sdkAction !== "agentSpend") {
      return refusalDocument(V, { reason: "A rooted-vault owner operation is never explained on its own: its authority IS the organizational root input. Supply the parent org-root-kas manifest.", failures: [{ name: "verifyWithinParent", detail: `only agentSpend is a standalone manifest; got ${JSON.stringify(isPlainObject(manifest.action) ? manifest.action.sdkAction : null)}` }], context: refusalContext(manifest), manifestHash: typeof manifest.manifestHash === "string" ? manifest.manifestHash : null });
    }
    let frozenTx = frozen;
    if (typeof frozenTx === "string") { try { frozenTx = JSON.parse(frozenTx); } catch { frozenTx = null; } }
    if (!isPlainObject(frozenTx) || !Array.isArray(frozenTx.inputs) || !Array.isArray(frozenTx.outputs)) {
      return refusalDocument(V, { reason: "The frozen transaction this payment describes was not supplied — a delegate payment is verified only against its exact frozen bytes.", failures: [{ name: "frozenSupplied", detail: "frozen (the canonical frozen transaction, JSON or object) is required" }], context: refusalContext(manifest), manifestHash: typeof manifest.manifestHash === "string" ? manifest.manifestHash : null });
    }
    const checks = [];
    const failures = [];
    verifyRootedKasVaultManifestV7({ manifest, frozen: frozenTx, redeemHex: typeof redeemHex === "string" ? redeemHex : null, check: (name, ok, detail) => { checks.push({ name, ok: !!ok }); if (!ok) failures.push({ name, detail }); } });
    /* the frozen transaction must be the one the manifest names */
    if (typeof manifest.transaction !== "object" || manifest.transaction === null || typeof manifest.transaction.txId !== "string") { failures.push({ name: "txIdDeclared", detail: "the manifest names no transaction id" }); checks.push({ name: "txIdDeclared", ok: false }); }
    const verificationSummary = { verdict: failures.length ? "REFUSED" : "VERIFIED", checks, failingChecks: [...new Set(failures.map((f) => f.name))].sort() };
    if (failures.length) {
      return refusalDocument(V, { reason: "This delegate payment FAILED local verification against the frozen transaction it describes and must not be signed or approved.", failures: failures.map((f) => ({ name: f.name, detail: f.detail })), context: refusalContext(manifest), manifestHash: manifest.manifestHash ?? null, txId: manifest.transaction && typeof manifest.transaction.txId === "string" ? manifest.transaction.txId : null, verification: verificationSummary });
    }
    const doc = baseDocument(V);
    const k = manifest.accounting.kas;
    const p = manifest.policy;
    const pol = p.agentPolicy;
    const tier = manifest.approverTier;
    const before = manifest.stateBefore.state;
    const after = manifest.stateAfter.state;
    const periods = BigInt(p.periodsElapsed);
    const spend = BigInt(k.payAmount);
    const newSpent = periods >= 1n ? spend : BigInt(pol.periodSpent) + spend;
    const remaining = BigInt(pol.periodBudget) - newSpent;
    doc.verdict = EXPLANATION_VERDICTS.VERIFIED_EXACT;
    doc.statement = "VERIFIED — this delegate payment description matches the frozen transaction exactly (amount, recipient, rules, reserve, approvals tier, successor script).";
    doc.manifestHash = manifest.manifestHash;
    doc.txId = manifest.transaction.txId;
    doc.network = { networkId: manifest.network.networkId };
    doc.ownership = { statement: KAS_OWNERSHIP_STATEMENT, profile: "policyvault-0.7-kas", candidate: true };
    doc.spend = {
      vaultId: manifest.vault.vaultId,
      covenantId: manifest.vault.covenantId,
      orgRootCovenantId: manifest.vault.orgRootCovenantId,
      summary: KAS_VAULT_ACTION_SUMMARY.agentSpend,
      payment: { amount: kasAmount(k.payAmount, "payment.amount"), recipient: p.recipient },
      policy: { ...kasPolicyDocument({ ...pol, recipients: null }, "agentPolicy"), periodsElapsed: periods.toString(), periodSpentAfter: kasAmount(newSpent, "policy.periodSpentAfter"), remainingBudgetAfter: kasAmount(remaining < 0n ? 0n : remaining, "policy.remainingBudgetAfter") },
      fee: { networkFee: kasAmount(k.fee, "fee"), reserveConsumed: kasAmount(k.reserveConsumed, "reserveConsumed"), fuelFunded: BigInt(k.externalIn) > 0n },
      approvals: { aboveThreshold: tier ? tier.aboveThreshold === true : false, requiredM: tier ? String(tier.requiredM) : "0", activeApprovers: tier && Array.isArray(tier.activeApprovers) ? tier.activeApprovers.slice() : [], approvalPackageCommitment: tier ? tier.approvalPackageCommitment ?? null : null },
      lockTime: String(p.lockTime),
      balances: { protectedBefore: kasAmount(k.predecessorProtected, "predecessorProtected"), protectedAfter: kasAmount(k.successorProtected, "successorProtected"), feeReserveBefore: kasAmount(k.predecessorFeeReserve, "predecessorFeeReserve"), feeReserveAfter: kasAmount(k.successorFeeReserve, "successorFeeReserve") },
      stateBefore: { stateId: manifest.stateBefore.stateId, outpoint: manifest.stateBefore.outpoint },
      stateAfter: { stateId: manifest.stateAfter.stateId },
      policyNonce: { before: String(before.policyNonce), after: String(after.policyNonce) },
      computeBudget: manifest.transaction.computeBudget
    };
    const warnings = [];
    if (doc.spend.approvals.aboveThreshold) warnings.push(warning("ABOVE_THRESHOLD"));
    if (periods >= 1n) warnings.push(warning("PERIOD_ROLLOVER"));
    warnings.push(warning(doc.spend.fee.fuelFunded ? "FUEL_PAYS_FEE" : "RESERVE_PAYS_FEE"));
    doc.warnings = warnings;
    doc.verification = verificationSummary;
    return deepFreeze(doc);
  } catch (e) {
    return refusalDocument(V, { reason: "The explanation engine failed internally — failing closed.", failures: [{ name: "explainInternal", detail: `${e && e.message ? e.message : String(e)}` }] });
  }
}

/* ------------------------------------------------------------------ */
/* humanReadable()                                                     */
/* ------------------------------------------------------------------ */

function refusalLines(doc, what) {
  const lines = [];
  lines.push("!! DO NOT SIGN !!");
  lines.push(`${what} REFUSED — this description FAILED verification and must not be signed.`);
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Failing checks: ${doc.refusal.failingChecks.join(", ")}.`);
  for (const f of doc.refusal.failures) lines.push(`- ${f.name}: ${sanitizeDetail(f.detail)}`);
  if (doc.context !== null) lines.push(`Context (from the manifest, NOT verified): manifest ${doc.context.manifestVersion === null ? "unknown" : sanitizeDetail(doc.context.manifestVersion)}, action ${doc.context.actionName === null ? "unknown" : sanitizeDetail(doc.context.actionName)}, network ${doc.context.networkId === null ? "unknown" : sanitizeDetail(doc.context.networkId)}.`);
  if (doc.txId !== null) lines.push(`Transaction id (NOT verified): ${sanitizeDetail(doc.txId)}.`);
  if (doc.manifestHash !== null) lines.push(`Manifest hash (NOT verified): ${sanitizeDetail(doc.manifestHash)}.`);
  lines.push("A refused description is never rendered as a normal transaction summary. Rebuild the request and verify again.");
  return lines;
}
function verifiedLines(doc) {
  const lines = [];
  lines.push(`ORGANIZATION ROOT APPROVAL — ${doc.authorization.actionName} (${doc.authorization.authorityClass}) — KAS TREASURY PROFILE (candidate).`);
  lines.push(`You are being asked to authorize: ${doc.authorization.summary}`);
  lines.push(doc.ownership.statement);
  if (doc.authorization.authorityClassForPreviousSet !== null) lines.push(`For the PREVIOUS owner set this action is ${doc.authorization.authorityClassForPreviousSet}.`);
  lines.push(`Organization ${doc.organization.orgId}; root covenant ${doc.organization.rootCovenantId}.`);
  lines.push(`Root outpoint being spent: ${outpointText(doc.organization.rootOutpoint)}.`);
  lines.push(ROOT_OUTPOINT_KILL_SWITCH_LINE);
  const satisfied = doc.quorum.satisfiedApprovals === null ? "not yet counted" : doc.quorum.satisfiedApprovals;
  lines.push(`Threshold: ${doc.quorum.requiredApprovals} of ${doc.quorum.activeOwnerSlots} active owner slot(s) must sign (from ${doc.quorum.quorumSource}); collected so far: ${satisfied}.`);
  for (const s of doc.quorum.expectedSignerSlots) lines.push(`Expected signer — slot ${s.slot}: ${s.publicKey}`);
  if (doc.quorum.expectedSignerSlots.length === 0) lines.push("Expected signers: none — this path is authorized by the pinned successor key, not by the owner slots.");
  lines.push(`Owner set before: ${doc.ownerSet.before.ownerM}-of-${doc.ownerSet.before.activeCount} (emergency quorum ${doc.ownerSet.before.emergencyK}, recovery quorum ${doc.ownerSet.before.recoveryM}).`);
  lines.push(`Owner set after: ${doc.ownerSet.after.ownerM}-of-${doc.ownerSet.after.activeCount} (emergency quorum ${doc.ownerSet.after.emergencyK}, recovery quorum ${doc.ownerSet.after.recoveryM}).`);
  for (const key of doc.ownerSet.added) lines.push(`Owner ADDED: ${key}`);
  for (const key of doc.ownerSet.removed) lines.push(`Owner REMOVED: ${key}`);
  if (doc.ownerSet.added.length === 0 && doc.ownerSet.removed.length === 0) lines.push("Owner keys: unchanged by this transaction.");
  lines.push(`Freeze flag: ${doc.rootState.frozenBefore} -> ${doc.rootState.frozenAfter}. Root nonce advances ${doc.rootState.nonceBefore} -> ${doc.rootState.nonceAfter}.`);
  lines.push(`Root state digest before: ${doc.rootState.beforeDigest}`);
  lines.push(`Root state digest after: ${doc.rootState.afterDigest}`);
  if (doc.timeLock !== null) lines.push(`Relative idle delay: this transaction is only valid once the root UTXO has been unspent for at least ${doc.timeLock.delayDaa} DAA score (input sequence ${doc.timeLock.minSequence}).`);
  lines.push(`Network fee: ${doc.fee.networkFee.kas} KAS. The root holds ${doc.fee.rootValueBefore.kas} KAS and keeps ${doc.fee.rootValueAfter.kas} KAS (loses ${doc.fee.rootValueLoss.kas} KAS; the covenant caps this at ${doc.fee.rootMaxFeePerTx.kas} KAS per transition).`);
  if (doc.vaultOperations.length === 0) lines.push("Vault operations in this transaction: none — this transaction only moves the root.");
  else {
    lines.push(`Vault operations in this transaction: ${doc.vaultOperations.length}. All of them happen together, or none of them do.`);
    doc.vaultOperations.forEach((v, i) => { for (const line of vaultOperationLines(v, i + 1)) lines.push(line); });
  }
  for (const w of doc.warnings) lines.push(`Warning ${w.code}: ${w.detail}`);
  lines.push(`Network: ${doc.network.networkId}. Contract: ${doc.organization.contractVersion} (vault profile policyvault-0.7-kas, CANDIDATE).`);
  lines.push(`Transaction id: ${doc.txId}. Manifest hash: ${doc.manifestHash}.`);
  lines.push(`Verification: PASSED — ${doc.statement}`);
  return lines;
}
function spendLines(doc) {
  const s = doc.spend;
  const lines = [];
  lines.push(`DELEGATE PAYMENT — ${s.payment.amount.kas} KAS from KAS vault ${s.vaultId} to ${s.payment.recipient}.`);
  lines.push(`You are being asked to ${s.approvals.aboveThreshold ? "APPROVE or SIGN" : "SIGN"}: ${s.summary}`);
  lines.push(doc.ownership.statement);
  lines.push(`Vault covenant ${s.covenantId}, pinned to root covenant ${s.orgRootCovenantId}. Vault outpoint being spent: ${outpointText(s.stateBefore.outpoint)}.`);
  lines.push(`Delegate ${s.policy.agentPk}: up to ${s.policy.maxPerSpend.kas} KAS per payment, ${s.policy.periodBudget.kas} KAS per ${s.policy.periodLengthDaa} DAA (period starts ${s.policy.periodStartDaa}; ${s.policy.periodsElapsed === "0" ? "same period" : `${s.policy.periodsElapsed} period(s) elapsed — a new period starts`}).`);
  lines.push(`Budget: spent ${s.policy.periodSpent.kas} KAS before, ${s.policy.periodSpentAfter.kas} KAS after this payment; ${s.policy.remainingBudgetAfter.kas} KAS remain in the period.`);
  lines.push(`Recipient ${s.payment.recipient} is proven under this delegate's allowlist (root ${s.policy.agentRecipientRoot}).`);
  lines.push(`Approvals: this payment is ${s.approvals.aboveThreshold ? "ABOVE" : "at or below"} the delegate's threshold of ${s.policy.approvalThreshold.kas} KAS${s.approvals.aboveThreshold ? ` — ${s.approvals.requiredM} of ${s.approvals.activeApprovers.length} vault approver(s) must co-sign this exact transaction` : " — the delegate's own signature is sufficient"}.`);
  for (const k of s.approvals.activeApprovers) lines.push(`  Approver slot: ${k}`);
  if (s.approvals.approvalPackageCommitment) lines.push(`  Approval package commitment: ${s.approvals.approvalPackageCommitment}`);
  lines.push(`Protected principal: ${s.balances.protectedBefore.kas} KAS -> ${s.balances.protectedAfter.kas} KAS. Fee reserve: ${s.balances.feeReserveBefore.kas} KAS -> ${s.balances.feeReserveAfter.kas} KAS.`);
  lines.push(`Network fee: ${s.fee.networkFee.kas} KAS (${s.fee.fuelFunded ? "paid by the delegate's own fee input" : `paid from the vault's fee reserve — ${s.fee.reserveConsumed.kas} KAS consumed`}; the delegate's fee cap is ${s.policy.agentMaxFeePerTx.kas} KAS).`);
  if (s.lockTime !== "0") lines.push(`Lock time: ${s.lockTime} — this payment cannot confirm before the chain reaches that DAA score.`);
  lines.push(`Vault policy nonce advances ${s.policyNonce.before} -> ${s.policyNonce.after}. Successor state id: ${s.stateAfter.stateId}.`);
  for (const w of doc.warnings) lines.push(`Warning ${w.code}: ${w.detail}`);
  lines.push(`Network: ${doc.network.networkId}. Vault profile policyvault-0.7-kas (CANDIDATE).`);
  lines.push(`Transaction id: ${doc.txId}. Manifest hash: ${doc.manifestHash}.`);
  lines.push(`Verification: PASSED — ${doc.statement}`);
  return lines;
}
function humanReadable(input) {
  const doc = structured(input);
  return deepFreeze(doc.verdict === EXPLANATION_VERDICTS.VERIFIED_EXACT ? verifiedLines(doc) : refusalLines(doc, "ORGANIZATION ROOT APPROVAL"));
}
function humanReadableSpend(input) {
  const doc = structuredSpend(input);
  return deepFreeze(doc.verdict === EXPLANATION_VERDICTS.VERIFIED_EXACT ? spendLines(doc) : refusalLines(doc, "DELEGATE PAYMENT"));
}

module.exports = {
  ORG_ROOT_KAS_EXPLANATION_VERSION_1,
  KAS_SPEND_EXPLANATION_VERSION_1,
  KAS_OWNERSHIP_STATEMENT,
  KAS_VAULT_ACTION_SUMMARY,
  KAS_WARNING_TEXT,
  EXPLANATION_VERDICTS,
  structured,
  structuredSpend,
  humanReadable,
  humanReadableSpend
};
