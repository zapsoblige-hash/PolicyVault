"use strict";

/*
 * PolicyVault v0.7 ORGANIZATIONAL ROOT — SIGNER-VISIBLE EXPLANATIONS (v1).
 *
 * Turns a `policyvault-org-root-manifest/1` (core/intent/org-root-manifest-v7)
 * into:
 *
 *   structured({ manifest, descriptors })
 *     -> a stable, versioned, JSON-safe explanation document
 *        ("policyvault-org-root-explanation/1") for APIs and agent workflows;
 *
 *   humanReadable({ manifest, descriptors })
 *     -> deterministic FIXED lines an owner reads BEFORE adding their slot
 *        signature to the 780-byte owner blob.
 *
 * WHAT THIS LAYER EXISTS TO SHOW (§5 / §11.1 I3 of
 * docs/postlaunch/v0.7-organizational-root-design.md):
 *   - WHAT the quorum is being asked to authorize: the action AND its
 *     AUTHORITY CLASS (AUTHORITY-REDUCING / -NEUTRAL / -EXPANDING /
 *     TERMINAL-for-the-previous-set);
 *   - the THRESHOLD required and how many approvals are collected;
 *   - exactly WHICH owner slots are expected to sign, in full;
 *   - the ROOT OUTPOINT KILL SWITCH: valid only while this root UTXO is
 *     unspent; no expiry;
 *   - EVERY vault operation riding in the SAME transaction, each with its
 *     own explanation;
 *   - the FEE and the bound on what the root itself may lose;
 *   - the RECOVERY / SUCCESSION warnings: both land FROZEN, the installed
 *     set must unfreeze with its FULL quorum, and both are gated by a
 *     RELATIVE input age (a dead-man's switch that ANY root transaction
 *     resets), not by a wall clock.
 *
 * BINDING RULES (fail closed, no default route):
 *   - The manifest is INDEPENDENTLY RE-VERIFIED here through
 *     verifyOrgRootIntentManifest. No caller-supplied verdict is accepted,
 *     so a fabricated "VERIFIED" cannot make an unverified manifest render
 *     as a normal approval screen.
 *   - Any manifest that is not a full verification pass produces a
 *     prominent REFUSAL that NAMES every failing check — never a normal
 *     rendering, and never any owner-set, amount or destination block.
 *   - Unknown manifest versions refuse. A STANDALONE
 *     `policyvault-rooted-vault-manifest/1` refuses with
 *     VERIFY_WITHIN_PARENT: a rooted vault's authority IS its root input,
 *     so rendering the vault half alone would present half of the security
 *     property as if it were the whole one (the same rule the intent router
 *     enforces). Rooted-vault operations are rendered as children of a
 *     VERIFIED org-root manifest.
 *   - NO truncation of keys, ids, outpoints or amounts: a shortened value
 *     can hide a substitution. Every identity renders in full.
 *   - Every amount is rendered through core/explain/kas.js — BigInt integer
 *     math only, never a JS number, never a float.
 *   - No network is named beyond the manifest's own `network.networkId`.
 *
 * Both entry points are TOTAL: they never throw. Malformed input and
 * internal errors produce a REFUSAL document (an error is never a pass).
 *
 * Portable shared core: pure CommonJS, zero external dependencies, no SDK
 * or server imports.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/explain/test/org-root-explain.test.js).
 * Explanations RENDER; they never authorize. Covenant authority moves only
 * through owner signatures over frozen transaction bytes, enforced by Kaspa
 * consensus.
 */

const {
  ORG_ROOT_MANIFEST_VERSION_1,
  ROOTED_VAULT_MANIFEST_VERSION_1,
  ORG_ROOT_EXPLANATION,
  verifyOrgRootIntentManifest
} = require("../intent/org-root-manifest-v7");
const { kasAmount } = require("./kas");
const { scaled } = require("./token-explain");

const ORG_ROOT_EXPLANATION_VERSION_1 = "policyvault-org-root-explanation/1";

const EXPLANATION_VERDICTS = Object.freeze({
  VERIFIED_EXACT: "VERIFIED_EXACT",
  REFUSED: "REFUSED"
});

/* The one-line kill-switch statement. Fixed text: a reader learns it once,
 * and a tampered manifest cannot reword it (the manifest's own fixed
 * explanation is separately asserted verbatim by the verifier). */
const ROOT_OUTPOINT_KILL_SWITCH_LINE =
  "Freshness: valid only while this root UTXO is unspent; no expiry. Spending the root outpoint invalidates every collected approval at once.";

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/*
 * Failure/warning DETAILS originate from manifest- or server-supplied
 * strings and are therefore untrusted when interpolated into a rendered
 * line: a crafted detail carrying newlines could otherwise inject a fake
 * "Verification: PASSED" into a DO-NOT-SIGN rendering, and bidi overrides
 * could visually reorder a key. Collapse every control and bidi character
 * to a single space and cap the length. The STRUCTURED document keeps the
 * raw detail (it is data, not a rendered line). Same rule as
 * core/explain/intent-explain.js sanitizeDetail (hostile review H-1).
 */
function sanitizeDetail(value) {
  const s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += isControl || isBidi ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? `${out.slice(0, 497)}...` : out;
}

function outpointText(op) {
  return `${op.transactionId}:${op.index}`;
}

/* The closed top-level key set of every explanation document — identical
 * for both verdicts (refusals carry null rendering blocks), so an API
 * consumer gets ONE stable shape. */
function baseDocument() {
  return {
    explanationVersion: ORG_ROOT_EXPLANATION_VERSION_1,
    verdict: null,
    statement: null,
    refusal: null,
    context: null,
    manifestHash: null,
    txId: null,
    network: null,
    organization: null,
    authorization: null,
    quorum: null,
    ownerSet: null,
    rootState: null,
    timeLock: null,
    freshness: null,
    fee: null,
    vaultOperations: null,
    warnings: null,
    verification: null
  };
}

function refusalDocument({ reason, failures, context = null, manifestHash = null, txId = null, verification = null }) {
  const names = [...new Set(failures.map((f) => f.name))].sort();
  const doc = baseDocument();
  doc.verdict = EXPLANATION_VERDICTS.REFUSED;
  doc.refusal = {
    reason: String(reason),
    failingChecks: names,
    failures: failures.map((f) => ({ name: String(f.name), detail: f.detail == null ? null : String(f.detail) }))
  };
  doc.context = context;
  doc.manifestHash = manifestHash;
  doc.txId = txId;
  doc.verification = verification;
  return deepFreeze(doc);
}

/* The minimal identity block a REFUSAL may carry, explicitly labeled
 * unverified. No owner keys, no amounts, no destinations: unverified values
 * are never rendered as facts. */
function refusalContext(manifest) {
  if (!isPlainObject(manifest)) return null;
  const ctx = { unverified: true, manifestVersion: null, actionName: null, networkId: null, rootCovenantId: null, rootOutpoint: null };
  if (typeof manifest.manifestVersion === "string") ctx.manifestVersion = manifest.manifestVersion;
  if (isPlainObject(manifest.action) && typeof manifest.action.name === "string") ctx.actionName = manifest.action.name;
  if (isPlainObject(manifest.network) && typeof manifest.network.networkId === "string") ctx.networkId = manifest.network.networkId;
  if (isPlainObject(manifest.root)) {
    if (typeof manifest.root.covenantId === "string") ctx.rootCovenantId = manifest.root.covenantId;
    if (isPlainObject(manifest.root.outpoint) && typeof manifest.root.outpoint.transactionId === "string") {
      ctx.rootOutpoint = { transactionId: manifest.root.outpoint.transactionId, index: manifest.root.outpoint.index };
    }
  }
  return ctx;
}

/* ------------------------------------------------------------------ */
/* action narration (fixed, table-driven — never model-generated)      */
/* ------------------------------------------------------------------ */

/*
 * One fixed sentence per root action. The text depends ONLY on the action
 * name, so two parties reading two renderings of the same action read the
 * same sentence.
 */
const ACTION_SUMMARY = Object.freeze({
  authorize:
    "AUTHORIZE — the owner quorum authorizes the vault operations listed in this transaction. The owner set, the thresholds and the freeze flag are all carried across unchanged; only the root nonce advances.",
  rotate:
    "ROTATE THE OWNER SET — the owner quorum installs a new set of owner keys and/or new thresholds on this organization's root.",
  freeze:
    "EMERGENCY FREEZE — the root is frozen. While it is frozen, no general owner operation on any vault of this organization can be authorized, and the root itself accepts only ROTATE, UNFREEZE, owner recovery and succession.",
  unfreeze: "UNFREEZE — the root returns to normal operation and general owner operations become possible again.",
  ownerRecover:
    "OWNER RECOVERY — the recovery quorum installs a NEW owner set after the root has been idle for the configured relative delay. This is the stranded-key path.",
  succession:
    "SUCCESSION — the pinned successor key replaces the entire owner set after the root has been idle for the configured relative delay. The previous owner set loses all authority."
});

/* One fixed sentence per rooted-vault operation. */
const VAULT_ACTION_SUMMARY = Object.freeze({
  ownerSetAgentRoot: "Replace this vault's delegate (agent) registry commitment.",
  ownerTopUpReserve: "Add KAS to this vault's fee reserve.",
  ownerPause: "Pause this vault — delegate spending stops until the owners unpause it.",
  ownerUnpause: "Unpause this vault — delegate spending resumes under the existing policy.",
  ownerEmergencyPause: "EMERGENCY-pause this vault on the lighter emergency quorum — delegate spending stops.",
  ownerRecover: "CLOSE this vault and pay everything it holds to the recovery key pinned when the vault was created. This is terminal.",
  tokenAgentSpend: "A delegate (agent) spend under the vault's existing policy."
});

/* ------------------------------------------------------------------ */
/* warnings (fixed codes + fixed text)                                 */
/* ------------------------------------------------------------------ */

const WARNING_TEXT = Object.freeze({
  LANDS_FROZEN:
    "This action lands the root FROZEN. The installed owners must deliberately UNFREEZE with their own approval quorum (M of N of the new set) before any general owner operation on any vault of this organization can be authorized again.",
  RELATIVE_AGE_GATE:
    "This path is gated by a RELATIVE input age, not by a wall clock: the root UTXO must have been unspent for at least the configured delay in DAA score. ANY root transaction resets that clock. While the root is unfrozen, routine authorization by its approval quorum can keep this path out of reach.",
  RECOVERY_INSTALLS_NEW_SET:
    "OWNER RECOVERY installs a NEW owner set on the RECOVERY quorum, which is smaller than or equal to the normal approval quorum. Every key it installs gains full authority once the set unfreezes.",
  SUCCESSION_TERMINAL_FOR_PREVIOUS_SET:
    "SUCCESSION installs a new owner set. A previous owner keeps authority only if that key is listed again; omitted keys lose authority. Owner 1 must change.",
  AUTHORITY_EXPANDING: "AUTHORITY-EXPANDING: a key or a path gains authority through this transaction.",
  AUTHORITY_REDUCING: "AUTHORITY-REDUCING: this transaction only removes authority; it cannot move funds and it cannot change the owner set.",
  EMERGENCY_QUORUM:
    "This transaction runs on the EMERGENCY quorum, which is lighter than the full owner quorum. The emergency quorum can only freeze the root and emergency-pause a vault; it can never change the owner set, unfreeze, or move funds.",
  OWNER_SET_CHANGES: "The owner set of this organization CHANGES in this transaction. Check every added and removed key below against your own records.",
  THRESHOLDS_CHANGE: "The approval thresholds of this organization CHANGE in this transaction.",
  RECOVERY_DISABLED: "Owner recovery is DISABLED for this root (the recovery quorum is 0). If the owner keys are lost below the quorum, no owner path can be recovered.",
  SUCCESSION_DISABLED: "Succession is DISABLED for this root (no successor key is pinned).",
  TERMINAL_VAULT_OPERATION:
    "A vault is CLOSED by this transaction. Its fee reserve and its entire token position pay to the recovery key pinned when that vault was created; this destination cannot be changed by this transaction.",
  APPROVALS_NOT_YET_COUNTED:
    "No collected-approval count is declared yet. This is the description an owner reads BEFORE the quorum is assembled; the finalizer refuses to build the transaction until the required number of slots have signed.",
  ROOT_VALUE_LOSS: "This transaction reduces the value held by the root itself. The covenant caps that loss per transition; the exact numbers are shown above."
});

function warning(code) {
  return { code, detail: WARNING_TEXT[code] };
}

/* ------------------------------------------------------------------ */
/* rooted-vault operation rendering (children of a VERIFIED parent)    */
/* ------------------------------------------------------------------ */

/*
 * A rooted-vault operation's own explanation. Rendered ONLY as a child of a
 * verified org-root manifest (see the module header): the vault's authority
 * IS the root input, so its verdict is the parent's.
 *
 * Token quantities render in ATOMIC units with a clearly-labeled display
 * form scaled by the descriptor's DISPLAY-ONLY decimals — reusing
 * core/explain/token-explain.js `scaled`, the same renderer the v0.5 token
 * explanation uses, so an operator reads one number format across
 * generations.
 */
function vaultOperationDocument(op) {
  const m = op.manifest;
  const a = m.action;
  const k = m.accounting.kas;
  const t = m.accounting.token;
  const dec = m.asset ? m.asset.decimalsDisplay : null;
  const tokenAmount = (atomic) => {
    if (atomic === null || atomic === undefined) return null;
    return { atomic: String(atomic), display: dec === null ? null : scaled(atomic, dec) };
  };

  const doc = {
    covenantId: op.covenantId,
    vaultId: op.vaultId,
    tokenCovenantId: op.tokenCovenantId,
    sdkAction: a.sdkAction,
    summary: VAULT_ACTION_SUMMARY[a.sdkAction] ?? null,
    role: a.role,
    terminal: a.terminal,
    mutationClass: a.mutationClass,
    opSelector: a.opSelector,
    requiresRootInput: a.requiresRootInput,
    requiredRootAction: a.requiredRootAction,
    expectFrozenAfter: a.expectFrozenAfter,
    orgRootCovenantId: m.vault.orgRootCovenantId,
    recoveryPk: m.vault.recoveryPk,
    asset: m.asset
      ? {
          assetId: m.asset.assetId,
          displayName: m.asset.displayName,
          descriptorHash: m.asset.descriptorHash,
          decimalsDisplay: m.asset.decimalsDisplay,
          trust: m.asset.trust,
          declaredIssuerPowers: Object.entries(m.asset.issuerPowers)
            .filter(([, on]) => on)
            .map(([name]) => name)
            .sort()
        }
      : null,
    token: {
      positionBefore: tokenAmount(t.positionBefore),
      spendAmount: tokenAmount(t.spendAmount),
      positionAfter: tokenAmount(t.positionAfter),
      recipient: t.recipient ?? null,
      recoveredToRecoveryPk: tokenAmount(t.recoveredToRecoveryPk)
    },
    kas: {
      feeReserveBefore: kasAmount(k.predecessorFeeReserve, "vault.predecessorFeeReserve"),
      feeReserveAfter: kasAmount(k.successorFeeReserve, "vault.successorFeeReserve"),
      reserveConsumed: kasAmount(k.reserveConsumed, "vault.reserveConsumed"),
      terminalPayout: kasAmount(k.terminalPayout, "vault.terminalPayout")
    },
    stateBefore: m.stateBefore ? { stateId: m.stateBefore.stateId, outpoint: m.stateBefore.outpoint } : null,
    stateAfter: m.stateAfter ? { stateId: m.stateAfter.stateId } : null,
    policyNonce:
      m.stateBefore && m.stateAfter && m.stateBefore.state && m.stateAfter.state
        ? { before: String(m.stateBefore.state.policyNonce), after: String(m.stateAfter.state.policyNonce) }
        : null,
    /* rc26 round-7 review R7-02: an ownerSetAgentRoot shows the RULES being installed — every policy of the new
     * delegate set the verifier bound stateAfter.agentRoot to (null for every other operation). */
    agentSet:
      a.sdkAction === "ownerSetAgentRoot" && m.policy && Array.isArray(m.policy.agentSet)
        ? m.policy.agentSet.map((p) => ({
            agentPk: p.agentPk,
            tokenMaxPerSpend: tokenAmount(p.tokenMaxPerSpend),
            tokenPeriodBudget: tokenAmount(p.tokenPeriodBudget),
            tokenPeriodSpent: tokenAmount(p.tokenPeriodSpent),
            periodLengthDaa: String(p.periodLengthDaa),
            periodStartDaa: String(p.periodStartDaa),
            agentMaxFeePerTx: kasAmount(p.agentMaxFeePerTx, "agentSet.agentMaxFeePerTx"),
            agentMaxCarryKas: kasAmount(p.agentMaxCarryKas, "agentSet.agentMaxCarryKas"),
            agentRecipientRoot: p.agentRecipientRoot,
            /* Codex checkpoint 11 (R7-02): the DESTINATIONS the owners are authorizing, never only their commitment */
            recipients: Array.isArray(p.recipients) ? p.recipients.map((r) => String(r)) : []
          }))
        : null,
    agentPolicy:
      m.policy && m.policy.agentPolicy
        ? {
            agentPk: m.policy.agentPolicy.agentPk,
            tokenMaxPerSpend: tokenAmount(m.policy.agentPolicy.tokenMaxPerSpend),
            tokenPeriodBudget: tokenAmount(m.policy.agentPolicy.tokenPeriodBudget),
            tokenPeriodSpent: tokenAmount(m.policy.agentPolicy.tokenPeriodSpent),
            periodLengthDaa: String(m.policy.agentPolicy.periodLengthDaa),
            periodsElapsed: String(m.policy.periodsElapsed),
            agentMaxFeePerTx: kasAmount(m.policy.agentPolicy.agentMaxFeePerTx, "agentPolicy.agentMaxFeePerTx"),
            agentRecipientRoot: m.policy.agentPolicy.agentRecipientRoot
          }
        : null,
    manifestHash: m.manifestHash
  };
  return doc;
}

/* Fixed lines for ONE vault operation. `index` is 1-based for display. */
function vaultOperationLines(v, index) {
  const lines = [];
  lines.push(`Vault operation ${index}: ${v.sdkAction} on vault ${v.vaultId} (covenant ${v.covenantId}).`);
  if (v.summary !== null) lines.push(`  ${v.summary}`);
  lines.push(`  Authority: ${v.mutationClass}; this operation requires the root to run ${v.requiredRootAction === null ? "no root action" : v.requiredRootAction}.`);
  lines.push(`  This vault is pinned to root covenant ${v.orgRootCovenantId}.`);
  if (v.asset !== null) {
    lines.push(`  Asset: ${v.asset.displayName} (assetId ${v.asset.assetId}, descriptor ${v.asset.descriptorHash}).`);
    lines.push(
      v.asset.declaredIssuerPowers.length
        ? `  Declared issuer powers (declared by the asset, not guaranteed by PolicyVault): ${v.asset.declaredIssuerPowers.join(", ")}.`
        : "  No declared issuer powers (declared-only; PolicyVault cannot discover undeclared powers)."
    );
  }
  if (v.token.spendAmount !== null && v.token.spendAmount.atomic !== "0") {
    const disp = v.token.spendAmount.display === null ? "" : ` (display: ${v.token.spendAmount.display})`;
    lines.push(`  Token spend: ${v.token.spendAmount.atomic} atomic units${disp}${v.token.recipient ? ` to ${v.token.recipient}` : ""}.`);
  }
  if (v.token.positionBefore !== null && v.token.positionAfter !== null) {
    lines.push(`  Token position: ${v.token.positionBefore.atomic} -> ${v.token.positionAfter.atomic} atomic units.`);
  }
  lines.push(`  Fee reserve: ${v.kas.feeReserveBefore.kas} KAS -> ${v.kas.feeReserveAfter.kas} KAS (consumed ${v.kas.reserveConsumed.kas} KAS).`);
  if (v.terminal) {
    lines.push(`  TERMINAL: this vault is CLOSED. Payout ${v.kas.terminalPayout.kas} KAS to the genesis-pinned recovery key ${v.recoveryPk}.`);
    if (v.token.recoveredToRecoveryPk !== null && v.token.recoveredToRecoveryPk.atomic !== "0") {
      lines.push(`  TERMINAL: the entire token position of ${v.token.recoveredToRecoveryPk.atomic} atomic units goes to the same recovery key.`);
    }
  }
  if (v.agentPolicy !== null) {
    lines.push(
      `  Delegate policy: agent ${v.agentPolicy.agentPk}, per-spend cap ${v.agentPolicy.tokenMaxPerSpend.atomic}, period budget ${v.agentPolicy.tokenPeriodBudget.atomic}, spent this period ${v.agentPolicy.tokenPeriodSpent.atomic}.`
    );
  }
  if (v.agentSet !== null) {
    if (v.agentSet.length === 0) lines.push("  New delegate policy set: EMPTY — after this operation no delegate can spend from this vault until a new set is installed.");
    else lines.push(`  New delegate policy set (${v.agentSet.length} ${v.agentSet.length === 1 ? "policy" : "policies"}) — these are the RULES being installed; the successor agentRoot is their Merkle root:`);
    for (const p of v.agentSet) {
      lines.push(
        `    agent ${p.agentPk}: per-spend cap ${p.tokenMaxPerSpend.atomic}, period budget ${p.tokenPeriodBudget.atomic} per ${p.periodLengthDaa} DAA (period starts ${p.periodStartDaa}, spent so far ${p.tokenPeriodSpent.atomic}), fee cap ${p.agentMaxFeePerTx.kas} KAS per transaction, KAS carry cap ${p.agentMaxCarryKas.kas} KAS.`
      );
      lines.push(`      may pay ONLY these ${p.recipients.length} recipient(s): ${p.recipients.join(", ")}`);
    }
  }
  if (v.policyNonce !== null) lines.push(`  Vault policy nonce advances ${v.policyNonce.before} -> ${v.policyNonce.after}.`);
  return lines;
}

/* ------------------------------------------------------------------ */
/* structured()                                                        */
/* ------------------------------------------------------------------ */

function structured(input) {
  const { manifest, descriptors, redeemScripts } = input && typeof input === "object" ? input : {};
  try {
    if (!isPlainObject(manifest)) {
      return refusalDocument({
        reason: "No organizational-root manifest was supplied — failing closed.",
        failures: [{ name: "manifestSupplied", detail: "an org-root manifest object is required" }]
      });
    }
    if (manifest.manifestVersion === ROOTED_VAULT_MANIFEST_VERSION_1) {
      return refusalDocument({
        reason:
          "A rooted-vault manifest is never explained on its own: a rooted vault has NO owner key, its authority IS the organizational root input, and rendering the vault half alone would present half of the security property as the whole one.",
        failures: [
          {
            name: "verifyWithinParent",
            detail: `${ROOTED_VAULT_MANIFEST_VERSION_1} is explained inside its parent ${ORG_ROOT_MANIFEST_VERSION_1} — supply the parent manifest`
          }
        ],
        context: refusalContext(manifest),
        manifestHash: typeof manifest.manifestHash === "string" ? manifest.manifestHash : null
      });
    }
    if (manifest.manifestVersion !== ORG_ROOT_MANIFEST_VERSION_1) {
      return refusalDocument({
        reason: "Unknown manifest version — failing closed (no default route).",
        failures: [
          {
            name: "manifestVersion",
            detail: `expected ${ORG_ROOT_MANIFEST_VERSION_1}, got ${JSON.stringify(manifest.manifestVersion)}`
          }
        ],
        context: refusalContext(manifest)
      });
    }

    /* INDEPENDENT re-verification — never a caller-supplied verdict. */
    const verification = verifyOrgRootIntentManifest({ manifest, descriptors: descriptors || {}, redeemScripts: redeemScripts || {} });
    const verificationSummary = {
      verdict: verification.verdict,
      checks: verification.checks.map((c) => ({ name: c.name, ok: c.ok })),
      failingChecks: [...new Set(verification.failures.map((f) => f.name))].sort()
    };
    if (verification.verdict !== "VERIFIED") {
      return refusalDocument({
        reason: "This organizational-root approval FAILED local verification against the frozen transaction it describes and must not be signed.",
        failures: verification.failures.map((f) => ({ name: f.name, detail: f.detail })),
        context: refusalContext(manifest),
        manifestHash: manifest.manifestHash ?? null,
        txId: manifest.transaction && typeof manifest.transaction.txId === "string" ? manifest.transaction.txId : null,
        verification: verificationSummary
      });
    }

    /* ---- VERIFIED: render ---- */
    const doc = baseDocument();
    const a = manifest.action;
    const before = manifest.ownerSet.before;
    const after = manifest.ownerSet.after;
    const changes = manifest.ownerSet.changes;

    doc.verdict = EXPLANATION_VERDICTS.VERIFIED_EXACT;
    doc.statement = verification.statement;
    doc.manifestHash = manifest.manifestHash;
    doc.txId = manifest.transaction.txId;
    doc.network = { networkId: manifest.network.networkId };

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

    doc.authorization = {
      actionName: a.name,
      actionCode: a.code === null ? null : String(a.code),
      entrypoint: a.entrypoint,
      authorityClass: a.authorityClass,
      authorityClassForPreviousSet: a.authorityClassForPreviousSet,
      summary: ACTION_SUMMARY[a.name] ?? null
    };

    const required = BigInt(a.requiredApprovals);
    const satisfied = a.satisfiedApprovals === null ? null : BigInt(a.satisfiedApprovals);
    doc.quorum = {
      quorumSource: a.quorumSource,
      requiredApprovals: required.toString(),
      satisfiedApprovals: satisfied === null ? null : satisfied.toString(),
      quorumSatisfied: satisfied === null ? null : satisfied >= required,
      activeOwnerSlots: String(before.activeCount),
      ownerM: before.ownerM,
      emergencyK: before.emergencyK,
      recoveryM: before.recoveryM,
      expectedSignerSlots: a.expectedSignerSlots.map((s) => ({ slot: s.slot, publicKey: s.publicKey }))
    };

    doc.ownerSet = {
      before: { activeCount: String(before.activeCount), ownerM: before.ownerM, emergencyK: before.emergencyK, recoveryM: before.recoveryM, slots: before.slots.map((s) => ({ slot: s.slot, publicKey: s.publicKey })) },
      after: { activeCount: String(after.activeCount), ownerM: after.ownerM, emergencyK: after.emergencyK, recoveryM: after.recoveryM, slots: after.slots.map((s) => ({ slot: s.slot, publicKey: s.publicKey })) },
      added: changes.added.slice(),
      removed: changes.removed.slice(),
      thresholdsChanged: changes.thresholdsChanged === true,
      frozenChanged: changes.frozenChanged === true
    };

    doc.rootState = {
      beforeDigest: manifest.rootState.before.digest,
      afterDigest: manifest.rootState.after.digest,
      successorTailHex: manifest.rootState.after.tailHex,
      frozenBefore: String(manifest.rootState.before.state.frozen),
      frozenAfter: String(manifest.rootState.after.state.frozen),
      nonceBefore: String(manifest.rootState.before.state.rootNonce),
      nonceAfter: String(manifest.rootState.after.state.rootNonce)
    };

    const minSequence = BigInt(a.minSequence);
    doc.timeLock =
      minSequence > 0n
        ? {
            kind: "RELATIVE_INPUT_AGE",
            minSequence: minSequence.toString(),
            delayDaa: a.name === "succession" ? manifest.root.template.successionDelayDaa : manifest.root.template.recoveryDelayDaa,
            resetByAnyRootTransaction: true
          }
        : null;

    doc.freshness = {
      kind: manifest.freshness.kind,
      rootOutpoint: { transactionId: manifest.freshness.rootOutpoint.transactionId, index: manifest.freshness.rootOutpoint.index },
      expiry: null,
      statement: ROOT_OUTPOINT_KILL_SWITCH_LINE
    };

    doc.fee = {
      networkFee: kasAmount(manifest.fee.requiredFeeSompi, "fee.requiredFeeSompi"),
      rootMaxFeePerTx: kasAmount(manifest.fee.rootMaxFeePerTx, "fee.rootMaxFeePerTx"),
      rootValueLoss: kasAmount(manifest.fee.rootValueLoss, "fee.rootValueLoss"),
      rootValueBefore: kasAmount(manifest.root.valueBefore, "root.valueBefore"),
      rootValueAfter: kasAmount(manifest.root.valueAfter, "root.valueAfter")
    };

    doc.vaultOperations = manifest.vaultOperations.map((op) => vaultOperationDocument(op));

    /* ---- warnings: fixed codes, fixed text, deterministic order ---- */
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
    if (doc.vaultOperations.some((v) => v.terminal)) warnings.push(warning("TERMINAL_VAULT_OPERATION"));
    if (doc.quorum.satisfiedApprovals === null) warnings.push(warning("APPROVALS_NOT_YET_COUNTED"));
    if (BigInt(manifest.fee.rootValueLoss) > 0n) warnings.push(warning("ROOT_VALUE_LOSS"));
    doc.warnings = warnings;

    doc.verification = verificationSummary;
    return deepFreeze(doc);
  } catch (e) {
    /* An internal error is never a pass. */
    return refusalDocument({
      reason: "The explanation engine failed internally — failing closed.",
      failures: [{ name: "explainInternal", detail: `${e && e.message ? e.message : String(e)}` }]
    });
  }
}

/* ------------------------------------------------------------------ */
/* humanReadable()                                                     */
/* ------------------------------------------------------------------ */

function refusalLines(doc) {
  const lines = [];
  lines.push("!! DO NOT SIGN !!");
  lines.push("ORGANIZATION ROOT APPROVAL REFUSED — this description FAILED verification and must not be signed.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Failing checks: ${doc.refusal.failingChecks.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.name}: ${sanitizeDetail(f.detail)}`);
  }
  if (doc.context !== null) {
    lines.push(
      `Context (from the manifest, NOT verified): manifest ${doc.context.manifestVersion === null ? "unknown" : sanitizeDetail(doc.context.manifestVersion)}, action ${doc.context.actionName === null ? "unknown" : sanitizeDetail(doc.context.actionName)}, network ${doc.context.networkId === null ? "unknown" : sanitizeDetail(doc.context.networkId)}, root covenant ${doc.context.rootCovenantId === null ? "unknown" : sanitizeDetail(doc.context.rootCovenantId)}.`
    );
  }
  /* txId / manifestHash / context values are echoed from a manifest that did
   * NOT verify, so they are untrusted TEXT here and are sanitized exactly
   * like a failure detail — a crafted value must not be able to inject a
   * structural or verdict line into a DO-NOT-SIGN rendering. */
  if (doc.txId !== null) lines.push(`Transaction id (NOT verified): ${sanitizeDetail(doc.txId)}.`);
  if (doc.manifestHash !== null) lines.push(`Manifest hash (NOT verified): ${sanitizeDetail(doc.manifestHash)}.`);
  lines.push("A refused approval is never rendered as a normal transaction summary. Rebuild the request and verify again.");
  return lines;
}

function verifiedLines(doc) {
  const lines = [];
  lines.push(`ORGANIZATION ROOT APPROVAL — ${doc.authorization.actionName} (${doc.authorization.authorityClass}).`);
  lines.push(`You are being asked to authorize: ${doc.authorization.summary}`);
  if (doc.authorization.authorityClassForPreviousSet !== null) {
    lines.push(`For the PREVIOUS owner set this action is ${doc.authorization.authorityClassForPreviousSet}.`);
  }
  lines.push(`Organization ${doc.organization.orgId}; root covenant ${doc.organization.rootCovenantId}.`);
  lines.push(`Root outpoint being spent: ${outpointText(doc.organization.rootOutpoint)}.`);
  lines.push(ROOT_OUTPOINT_KILL_SWITCH_LINE);

  const satisfied = doc.quorum.satisfiedApprovals === null ? "not yet counted" : doc.quorum.satisfiedApprovals;
  lines.push(
    `Threshold: ${doc.quorum.requiredApprovals} of ${doc.quorum.activeOwnerSlots} active owner slot(s) must sign (from ${doc.quorum.quorumSource}); collected so far: ${satisfied}.`
  );
  for (const s of doc.quorum.expectedSignerSlots) {
    lines.push(`Expected signer — slot ${s.slot}: ${s.publicKey}`);
  }
  if (doc.quorum.expectedSignerSlots.length === 0) {
    lines.push("Expected signers: none — this path is authorized by the pinned successor key, not by the owner slots.");
  }

  lines.push(
    `Owner set before: ${doc.ownerSet.before.ownerM}-of-${doc.ownerSet.before.activeCount} (emergency quorum ${doc.ownerSet.before.emergencyK}, recovery quorum ${doc.ownerSet.before.recoveryM}).`
  );
  lines.push(
    `Owner set after: ${doc.ownerSet.after.ownerM}-of-${doc.ownerSet.after.activeCount} (emergency quorum ${doc.ownerSet.after.emergencyK}, recovery quorum ${doc.ownerSet.after.recoveryM}).`
  );
  for (const key of doc.ownerSet.added) lines.push(`Owner ADDED: ${key}`);
  for (const key of doc.ownerSet.removed) lines.push(`Owner REMOVED: ${key}`);
  if (doc.ownerSet.added.length === 0 && doc.ownerSet.removed.length === 0) {
    lines.push("Owner keys: unchanged by this transaction.");
  }
  lines.push(`Freeze flag: ${doc.rootState.frozenBefore} -> ${doc.rootState.frozenAfter}. Root nonce advances ${doc.rootState.nonceBefore} -> ${doc.rootState.nonceAfter}.`);
  lines.push(`Root state digest before: ${doc.rootState.beforeDigest}`);
  lines.push(`Root state digest after: ${doc.rootState.afterDigest}`);

  if (doc.timeLock !== null) {
    lines.push(
      `Relative idle delay: this transaction is only valid once the root UTXO has been unspent for at least ${doc.timeLock.delayDaa} DAA score (input sequence ${doc.timeLock.minSequence}).`
    );
  }

  lines.push(
    `Network fee: ${doc.fee.networkFee.kas} KAS. The root holds ${doc.fee.rootValueBefore.kas} KAS and keeps ${doc.fee.rootValueAfter.kas} KAS (loses ${doc.fee.rootValueLoss.kas} KAS; the covenant caps this at ${doc.fee.rootMaxFeePerTx.kas} KAS per transition).`
  );

  if (doc.vaultOperations.length === 0) {
    lines.push("Vault operations in this transaction: none — this transaction only moves the root.");
  } else {
    lines.push(`Vault operations in this transaction: ${doc.vaultOperations.length}. All of them happen together, or none of them do.`);
    doc.vaultOperations.forEach((v, i) => {
      for (const line of vaultOperationLines(v, i + 1)) lines.push(line);
    });
  }

  for (const w of doc.warnings) lines.push(`Warning ${w.code}: ${w.detail}`);

  lines.push(`Network: ${doc.network.networkId}. Contract: ${doc.organization.contractVersion}.`);
  lines.push(`Transaction id: ${doc.txId}. Manifest hash: ${doc.manifestHash}.`);
  lines.push(`Verification: PASSED — ${doc.statement}`);
  return lines;
}

/*
 * Deterministic fixed lines for a signing owner. TOTAL: never throws;
 * refusals render as prominent DO-NOT-SIGN lines naming every failing
 * check. Same input -> byte-identical output.
 */
function humanReadable(input) {
  const doc = structured(input);
  const lines = doc.verdict === EXPLANATION_VERDICTS.VERIFIED_EXACT ? verifiedLines(doc) : refusalLines(doc);
  return deepFreeze(lines);
}

module.exports = {
  ORG_ROOT_EXPLANATION_VERSION_1,
  EXPLANATION_VERDICTS,
  ROOT_OUTPOINT_KILL_SWITCH_LINE,
  ACTION_SUMMARY,
  VAULT_ACTION_SUMMARY,
  WARNING_TEXT,
  ORG_ROOT_EXPLANATION,
  structured,
  humanReadable
};
