"use strict";

/*
 * policyvault-rooted-kas-vault-manifest/1 — the closed-schema, hash-committed
 * description of ONE v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT transition, plus
 * its deterministic LOCAL VERIFICATION against the frozen transaction bytes;
 * and policyvault-org-root-kas-manifest/1 — the org-root-level wrapper that
 * embeds every rooted-KAS-vault owner operation riding in the SAME
 * transaction, exactly like core/intent/org-root-manifest-v7.js does for the
 * rooted PAYMENT profile.
 *
 * SIBLING of core/intent/org-root-manifest-v7.js. This is a SEPARATE module
 * (not a patch to it) because that file's org-root wrapper hard-wires calls
 * to the PAYMENT profile's buildRootedVaultManifestV7/verifyRootedVaultManifestV7
 * inside its vaultOperations loop — extending it in place would touch
 * production-byte-verified payment-profile code. The ROOT-side logic
 * (rootFactsFrom/setSummary/the org-root body shape) is restated here
 * VERBATIM against the identical `rootAuthority` shape vault-builders-v7-kas.js
 * produces (see finishBuildV7Kas) — never re-derived, only re-typed for this
 * profile's vaultOperations wiring.
 *
 * WHAT CHANGES vs the payment profile's manifest, and only this:
 *   - the vault state is the frozen v0.4.1 shape (protectedValue, feeReserve,
 *     paused, agentRoot, approver1..10/approverSlots, approvalM, policyNonce)
 *     instead of the payment profile's (feeReserve, paused, agentRoot,
 *     policyNonce + a token descriptor) — no descriptor, no token family;
 *   - ownerControl carries SEVEN selectors (0..6: setAgentRoot, setApprovers,
 *     topUp, topUpReserve, pause, unpause, EMERGENCY pause) instead of the
 *     payment profile's five;
 *   - the DELEGATE path is `agentSpend` (frozen v0.4.1 ABI) and carries the
 *     VAULT-LEVEL M-of-N APPROVAL TIER above a per-agent threshold — a
 *     DIFFERENT M-of-N mechanism from the organizational root's, shown here
 *     as COUNTS + PUBLIC KEYS + DIGESTS (approvalM required, the active
 *     approver public keys, and — when an approval package is supplied —
 *     its commitment digest), never raw collected signatures;
 *   - a delegate spend is a STANDALONE manifest (buildRootedKasVaultManifestV7
 *     used directly, exactly like tokenAgentSpend in the payment profile's
 *     own vector generator) since it never touches the root; owner
 *     operations are embedded INSIDE the org-root-kas manifest exactly like
 *     the payment profile's owner operations.
 *
 * Status: IMPLEMENTED (SDK-facing core module, portable). Exercised by
 * sdk/tools/gen-v7-kas-vectors.js + tests/vm/tests/v7_kas_sdk_integration.rs
 * (production-byte proof) and core/crossruntime portability.
 */

const { canonicalJsonStringify, computeManifestHashV1 } = require("./canonical");
const { ownGet } = require("../model/own-get"); // rc12 review R-02: own-property action lookups (prototype keys fail closed)
const {
  normalizeRootStateV7,
  normalizeRootTemplateV7,
  rootStateToJsonV7,
  rootStateTailHexV7,
  computeRootStateDigestV7
} = require("../model/vault-state-v7-root");
const { resolveRootActionV7, requiredApprovalsV7, activeOwnerSlotsV7, normalizeOwnerSetV7, OWNER_SLOTS_V7 } = require("../model/owner-set-v7");
const { normalizeTemplateV7Kas, resolveOwnerOpAuthorityV7Kas, OWNER_OP_SELECTOR_V7_KAS, templateToJsonV7Kas, CONTRACT_VERSION_V7_KAS } = require("../model/vault-state-v7-kas");
const { normalizeStateV4, stateToJsonV4, MAX_APPROVERS } = require("../model/vault-state-v4");
const vaultScriptV7Kas = require("./vault-script-v7-kas"); // R7-04 closure: shared-core reconstruction of the predecessor + successor scripts (candidate v0.7-kas skeleton)
const { isPaymentGenerationScriptV7 } = require("./vault-script-v7"); // cross-generation guard: a frozen v0.7-payment script is never accepted as a KAS vault
const { normalizeAgentPolicyV4, verifyAgentProofV4, foldAgentPolicyV4, buildAgentTreeV4 } = require("../model/agent-merkle-v4");
const { verifyRecipientProof, buildRecipientTree } = require("../model/recipient-merkle-v3");
const { ROOT_STATE_LEN_V7 } = require("../model/vault-state-v7-root"); // Codex checkpoint 7
const { blake2bHex } = require("../assets/blake2b"); // Codex checkpoint 7
function hexToBytes(hex) { const out = new Uint8Array(hex.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16); return out; }
const rootScriptV7 = require("./root-script-v7"); // rc21 review R6-03: the same root-script binding as the v7 verifier
const { V7_KAS_BUDGET, selectComputeBudgetV7Kas, selectRootComputeBudgetV7 } = require("../model/compute-budget-v7-kas"); // Codex checkpoint 6 (UX-02 / UX-13): budgets DERIVED from the reviewed operation (parity with the payment verifier)

const ORG_ROOT_KAS_MANIFEST_VERSION_1 = "policyvault-org-root-kas-manifest/1";
const ROOTED_KAS_VAULT_MANIFEST_VERSION_1 = "policyvault-rooted-kas-vault-manifest/1";
const VERIFIED_STATEMENT = "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.";

const ORG_ROOT_KAS_EXPLANATION =
  "This transaction spends your organization's PolicyVault root. The root holds the owner set, " +
  "the approval thresholds, the freeze flag and a strictly increasing nonce; it never pays anyone " +
  "and it can never be dissolved. Approving means: the named action runs, the named owner slots " +
  "must sign, and every ROOTED KAS SAFE-PAYMENT VAULT operation listed below happens in the SAME " +
  "transaction or none of them do. Your approval is bound to this exact transaction and to this " +
  "exact root outpoint — there is no expiry, because spending the root outpoint is what " +
  "invalidates every collected approval at once. A rooted vault has no owner key: this root input " +
  "IS the owner authority. This vault ALSO has its own, separate vault-level M-of-N approver tier " +
  "above a per-agent spending threshold — that tier is a completely different mechanism from the " +
  "organizational root and is never satisfied by root owners signing.";

/* role / terminal / mutation class per SDK action (mirrors ROOTED_VAULT_ACTIONS). */
const ROOTED_KAS_VAULT_ACTIONS = Object.freeze({
  ownerSetAgentRoot: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-EXPANDING" }),
  ownerSetApprovers: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-EXPANDING" }),
  ownerTopUp: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-NEUTRAL" }),
  ownerTopUpReserve: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-NEUTRAL" }),
  ownerPause: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-REDUCING" }),
  ownerUnpause: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-EXPANDING" }),
  ownerEmergencyPause: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-REDUCING" }),
  ownerRecover: Object.freeze({ role: "owners", terminal: true, mutationClass: "TERMINAL" }),
  agentSpend: Object.freeze({ role: "agent", terminal: false, mutationClass: "AUTHORITY-NEUTRAL" })
});

function refuse(code, message) {
  const e = new Error(message);
  e.code = code;
  throw e;
}
function digits(v, where) {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) refuse("SCHEMA_INVALID", `${where} must be a non-negative digit string`);
  return BigInt(v);
}
function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* the ROOTED KAS VAULT controller manifest (one vault operation)       */
/* ------------------------------------------------------------------ */

function buildRootedKasVaultManifestV7({ build, approvalPackage = null }) {
  if (!build || build.contractVersion !== "policyvault-0.7-kas" || build.kind !== "transition") {
    refuse("SCHEMA_INVALID", "a v0.7-kas transition build is required");
  }
  const info = ownGet(ROOTED_KAS_VAULT_ACTIONS, build.action);
  if (!info) refuse("UNKNOWN_ACTION", `unknown v0.7-kas rooted-vault action ${JSON.stringify(build.action)} — failing closed`);
  const authority = build.action === "agentSpend" ? null : resolveOwnerOpAuthorityV7Kas(build.action);
  const body = {
    manifestVersion: ROOTED_KAS_VAULT_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    vault: {
      contractVersion: build.contractVersion,
      vaultId: build.template.vaultId,
      covenantId: build.covenantId,
      orgRootCovenantId: build.template.orgRootCovenantId,
      rootTemplateVmHash: build.template.rootTemplateVmHash,
      rootGeometry: { prefixLen: build.template.rootPrefixLen, stateLen: build.template.rootStateLen, suffixLen: build.template.rootSuffixLen },
      recoveryPk: build.template.recoveryPk
    },
    action: {
      sdkAction: build.action,
      role: info.role,
      terminal: info.terminal,
      mutationClass: info.mutationClass,
      opSelector: build.callExtra.opSelector ?? null,
      requiresRootInput: build.hasRootInput,
      requiredRootAction: authority ? authority.rootActionName : null,
      expectFrozenAfter: authority ? authority.expectFrozenAfter.toString() : null
    },
    stateBefore: { stateId: build.predecessorStateId, state: build.stateJson, outpoint: build.predecessorOutpoint },
    stateAfter: info.terminal ? null : { stateId: build.successorStateId, state: build.successorState },
    accounting: { kas: { ...build.accounting.kas } },
    approverTier:
      build.action === "agentSpend"
        ? {
            /* the VAULT-LEVEL M-of-N approver tier, shown as COUNTS + PUBLIC
             * KEYS + DIGESTS — NEVER raw collected signatures. This is the
             * frozen v0.4.1 approver tier, a completely separate mechanism
             * from the organizational root's M-of-N. */
            approvalThreshold: build.callExtra.approvalThreshold,
            requiredM: build.stateJson.approvalM,
            activeApprovers: build.stateJson.approverSlots.filter((k) => k !== "00".repeat(32)),
            aboveThreshold: build.aboveThreshold,
            approvalPackageCommitment: approvalPackage ? approvalPackage.commitment : null
          }
        : null,
    policy:
      build.action === "agentSpend"
        ? {
            agentPolicy: build.callExtra
              ? {
                  agentPk: build.callExtra.agentPk,
                  maxPerSpend: build.callExtra.maxPerSpend,
                  periodBudget: build.callExtra.periodBudget,
                  periodLengthDaa: build.callExtra.periodLengthDaa,
                  periodStartDaa: build.callExtra.periodStartDaa,
                  periodSpent: build.callExtra.periodSpent,
                  approvalThreshold: build.callExtra.approvalThreshold,
                  agentMaxFeePerTx: build.callExtra.agentMaxFeePerTx,
                  agentRecipientRoot: build.callExtra.agentRecipientRoot
                }
              : null,
            agentProof: build.agentProof ? { ...build.agentProof } : null,
            recipient: build.payment.recipient,
            recipientProof: build.recipientProof ? { ...build.recipientProof } : null,
            periodsElapsed: build.callExtra.periodsElapsed,
            lockTime: build.frozen.lockTime.toString()
          }
        : build.action === "ownerSetAgentRoot"
          ? {
              /* rc26 round-7 review R7-02 (parity with the payment profile): the full new policy set travels in the manifest. */
              recoveryPk: null,
              agentSet: Array.isArray(build.agentSet) ? build.agentSet.map((policy) => ({ ...policy })) : null
            }
          : { recoveryPk: build.action === "ownerRecover" ? build.template.recoveryPk : null },
    transaction: { txId: build.txId, computeBudget: build.computeBudget, requiredFeeSompi: build.requiredFeeSompi }
  };
  return deepFreeze({ ...body, manifestHash: computeManifestHashV1(body) });
}

/* The per-selector state effect the covenant's mutually exclusive branches
 * allow (contracts/PolicyVault.v0.7-kas.sil ownerControl, carried byte-for-
 * byte from the frozen v0.4.1 base except selector 6, the new EMERGENCY
 * pause — identical state effect to selector 4). */
function selectorEffectHoldsV7Kas(sel, before, after) {
  switch (sel) {
    case OWNER_OP_SELECTOR_V7_KAS.ownerSetAgentRoot:
      return (
        after.protectedValue === before.protectedValue &&
        after.feeReserve === before.feeReserve &&
        after.paused === before.paused &&
        approversEqual(before, after) &&
        after.policyNonce === before.policyNonce + 1n
      );
    case OWNER_OP_SELECTOR_V7_KAS.ownerSetApprovers:
      return (
        after.protectedValue === before.protectedValue &&
        after.feeReserve === before.feeReserve &&
        after.paused === before.paused &&
        after.agentRoot === before.agentRoot &&
        after.policyNonce === before.policyNonce + 1n
      );
    case OWNER_OP_SELECTOR_V7_KAS.ownerTopUp:
      return (
        after.protectedValue > before.protectedValue &&
        after.feeReserve === before.feeReserve &&
        after.paused === before.paused &&
        after.agentRoot === before.agentRoot &&
        approversEqual(before, after) &&
        after.policyNonce === before.policyNonce
      );
    case OWNER_OP_SELECTOR_V7_KAS.ownerTopUpReserve:
      return (
        after.feeReserve > before.feeReserve &&
        after.protectedValue === before.protectedValue &&
        after.paused === before.paused &&
        after.agentRoot === before.agentRoot &&
        approversEqual(before, after) &&
        after.policyNonce === before.policyNonce
      );
    case OWNER_OP_SELECTOR_V7_KAS.ownerPause:
    case OWNER_OP_SELECTOR_V7_KAS.ownerEmergencyPause:
      return (
        before.paused === 0n &&
        after.paused === 1n &&
        after.protectedValue === before.protectedValue &&
        after.feeReserve === before.feeReserve &&
        after.agentRoot === before.agentRoot &&
        approversEqual(before, after) &&
        after.policyNonce === before.policyNonce
      );
    case OWNER_OP_SELECTOR_V7_KAS.ownerUnpause:
      return (
        before.paused === 1n &&
        after.paused === 0n &&
        after.protectedValue === before.protectedValue &&
        after.feeReserve === before.feeReserve &&
        after.agentRoot === before.agentRoot &&
        approversEqual(before, after) &&
        after.policyNonce === before.policyNonce
      );
    default:
      return false;
  }
}
function approversEqual(before, after) {
  /* `before`/`after` are normalizeStateV4() OBJECTS — the padded 10-slot
   * array lives at `.approvers` there; `.approverSlots` is only the JSON
   * (stateToJsonV4) field name. */
  if (before.approvers.length !== MAX_APPROVERS || after.approvers.length !== MAX_APPROVERS) return false;
  for (let i = 0; i < MAX_APPROVERS; i += 1) if (before.approvers[i] !== after.approvers[i]) return false;
  return before.approvalM === after.approvalM;
}

/*
 * Verify ONE rooted-KAS-vault operation against the frozen transaction it
 * rides in. `frozen` is the parsed canonical transaction shared by every
 * operation in the manifest, so a vault op can never be verified against a
 * different transaction than the root it claims to ride.
 */
function verifyRootedKasVaultManifestV7({ manifest, frozen, redeemHex = null, check }) {
  if (manifest.manifestVersion !== ROOTED_KAS_VAULT_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown rooted-kas-vault manifest version — failing closed");
  const { manifestHash, ...body } = manifest;
  const tag = `vault[${manifest.vault.covenantId.slice(0, 8)}].`;
  check(`${tag}manifestHash`, computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
  const info = ownGet(ROOTED_KAS_VAULT_ACTIONS, manifest.action.sdkAction);
  check(`${tag}action`, !!info && info.role === manifest.action.role && info.terminal === manifest.action.terminal && info.mutationClass === manifest.action.mutationClass, "role/terminal/class derived from the action table");
  if (!info) return;

  /* THE DECLARED TEMPLATE PINS MUST BE A WELL-FORMED v0.7-kas ROOTED VAULT
   * (identical discipline to the payment profile's I3c-F2 hardening). */
  let templatePinFailure = null;
  try {
    normalizeTemplateV7Kas({
      vaultId: manifest.vault.vaultId,
      orgRootCovenantId: manifest.vault.orgRootCovenantId,
      rootTemplateVmHash: manifest.vault.rootTemplateVmHash,
      rootPrefixLen: manifest.vault.rootGeometry.prefixLen,
      rootStateLen: manifest.vault.rootGeometry.stateLen,
      rootSuffixLen: manifest.vault.rootGeometry.suffixLen,
      recoveryPk: manifest.vault.recoveryPk
    });
  } catch (e) {
    templatePinFailure = `${e.code ?? "TEMPLATE_INVALID"}: ${e.message}`;
  }
  check(`${tag}templatePins`, templatePinFailure === null, templatePinFailure ?? "the declared template pins are a well-formed v0.7-kas rooted vault");

  const inputs = frozen.inputs;
  const outputs = frozen.outputs;
  const vaultIns = inputs.filter((i) => i.utxo.covenantId === manifest.vault.covenantId);
  /* rc26 round-7 review R7-01 (parity): every non-root input is spendable NOW (sequence 0); an owner operation never
   * carries a lock time. The agent spend's lockTime is bound exactly to its period rule (lockTimeBound). */
  check(`${tag}inputSequencesZero`, inputs.every((i) => i.utxo.covenantId === manifest.vault.orgRootCovenantId || String(i.sequence) === "0"), "every non-root input carries sequence 0 — no hidden relative lock");
  if (manifest.action.sdkAction !== "agentSpend") check(`${tag}lockTimeZero`, String(frozen.lockTime) === "0", `an owner operation never carries a lock time (frozen lockTime ${frozen.lockTime})`);
  const before = normalizeStateV4(manifest.stateBefore.state);
  check(
    `${tag}vaultInputValue`,
    vaultIns.length === 1 && vaultIns[0].utxo.amount === (before.protectedValue + before.feeReserve).toString(),
    "the vault input carries exactly protectedValue + feeReserve"
  );

  /* R7-04 CLOSURE (v0.7 enablement directive, 2026-09-10) — THE DECLARED PINS AND THE REVIEWED PREDECESSOR STATE ARE
   * BOUND TO THE VAULT THE TRANSACTION ACTUALLY SPENDS, for EVERY operation (terminal ones included), with the discipline
   * the frozen payment profile's verifier established (Codex checkpoints 6 + 7): the vault's predecessor redeem script is
   * REQUIRED; its P2SH must be the vault input's locking script (covered by every signature hash); its 441-byte state
   * region must decode to exactly the reviewed predecessor state under the reviewed vaultId; the whole script rebuilt from
   * the DECLARED template pins (root covenant id + root template hash + root geometry + recovery key) around that state
   * must be byte for byte this redeem (core/intent/vault-script-v7-kas.js — the candidate generation's skeleton,
   * mechanically derived from real silverc output and proven against it); and the script must be of THIS candidate
   * generation, never the frozen v0.7-payment one. A declared geometry, template hash, recovery key or predecessor state
   * that is not the one compiled into the spent vault fails here, before any budget is derived from it and before any
   * wallet is invoked. */
  const redeemPresent = typeof redeemHex === "string" && /^[0-9a-f]+$/i.test(redeemHex) && redeemHex.length % 2 === 0;
  check(`${tag}vaultRedeemPresent`, redeemPresent, "the vault's predecessor redeem script must be supplied for every operation (terminal included): it is the evidence the declared pins and predecessor state are bound to");
  let parts = null;
  let pinsBound = false;
  let redeemPins = null; // the pins COMPILED INTO the spent script (decoded from the bound redeem) — the only trusted source for the recovery destination
  if (redeemPresent) {
    let parseError = null;
    try { parts = vaultScriptV7Kas.splitVaultRedeemHexV7Kas(redeemHex); } catch (e) { parseError = e && e.message ? e.message : String(e); }
    check(`${tag}vaultRedeemWellFormed`, parseError === null, parseError ?? "the carried redeem script splits into prefix / 441-byte state region / suffix");
    if (parts) {
      const inSpk = vaultIns.length === 1 && vaultIns[0].utxo && vaultIns[0].utxo.scriptPublicKey ? vaultIns[0].utxo.scriptPublicKey : {};
      const utxoBound = Number(inSpk.version || 0) === 0 && String(inSpk.scriptHex || "").toLowerCase() === vaultScriptV7Kas.p2shSpkHexOf(redeemHex);
      check(`${tag}vaultRedeemMatchesUtxo`, utxoBound, "P2SH of the carried redeem == the vault input's locking script (covered by every signature hash)");
      const dec = parts.decoded;
      check(`${tag}vaultRedeemStateAgrees`, dec.vaultId === String(manifest.vault.vaultId).toLowerCase() && JSON.stringify(dec.state) === JSON.stringify(stateToJsonV4(before)), "the redeem's 441-byte state region decodes to exactly the reviewed predecessor state under the reviewed vaultId");
      const paymentScript = isPaymentGenerationScriptV7(redeemHex);
      let decoded = null, decodeError = null;
      try { decoded = vaultScriptV7Kas.decodeVaultTemplatePinsV7Kas(redeemHex); } catch (e) { decodeError = e && e.message ? e.message : String(e); }
      const generationAgrees = manifest.vault.contractVersion === CONTRACT_VERSION_V7_KAS && decoded !== null && !paymentScript;
      check(
        `${tag}vaultGenerationAgrees`,
        generationAgrees,
        paymentScript
          ? "the vault input's script IS a frozen v0.7-payment vault presented as a v0.7-kas vault"
          : decoded === null
            ? `the vault input's script is not the candidate v0.7-kas generation: ${decodeError}`
            : manifest.vault.contractVersion !== CONTRACT_VERSION_V7_KAS
              ? `the manifest declares ${manifest.vault.contractVersion} for a v0.7-kas script`
              : "the spent script is the candidate v0.7-kas generation and the manifest declares it"
      );
      let rebuilt = null, rebuildError = null;
      try { rebuilt = vaultScriptV7Kas.reconstructVaultScriptHexV7Kas({ template: vaultScriptV7Kas.templatePinsFromManifestVaultV7Kas(manifest.vault), state: manifest.stateBefore.state }); } catch (e) { rebuildError = e && e.message ? e.message : String(e); }
      pinsBound = rebuildError === null && rebuilt === String(redeemHex).toLowerCase();
      check(
        `${tag}templatePinsBound`,
        pinsBound,
        rebuildError
          ? `the v0.7-kas script could not be rebuilt from the declared template pins: ${rebuildError}`
          : pinsBound
            ? "the v0.7-kas script rebuilt from the DECLARED template pins (root covenant id + template hash + geometry, recovery key) around the reviewed predecessor state is byte for byte the vault input's revealed redeem"
            : `the declared template pins / predecessor state do not rebuild the vault's revealed redeem script (${decoded ? "a substituted root geometry, root template hash, recovery key or predecessor state" : "the revealed script is not a v0.7-kas vault"})`
      );
      if (pinsBound && utxoBound && decoded) redeemPins = decoded.pins;
    }
  }
  if (manifest.action.sdkAction !== "agentSpend") { // Codex checkpoint 6 (UX-02 / UX-13): an owner op's vault-input budget is derived from the op + the pinned root geometry (a delegate spend's depends on proof depths the manifest does not carry — left to the builder's own sufficiency assertion)
    let expectedVaultBudget = null, budgetError = null;
    try { expectedVaultBudget = selectComputeBudgetV7Kas({ operation: manifest.action.sdkAction, rootPrefixLen: manifest.vault.rootGeometry.prefixLen, rootSuffixLen: manifest.vault.rootGeometry.suffixLen }); } catch (e) { budgetError = e && e.message ? e.message : String(e); }
    check(`${tag}vaultComputeBudgetBound`, budgetError === null && vaultIns.length === 1 && Number.isInteger(vaultIns[0].computeBudget) && vaultIns[0].computeBudget === expectedVaultBudget && String(manifest.transaction.computeBudget) === String(expectedVaultBudget), budgetError ? `the vault input's compute budget could not be derived: ${budgetError}` : `the vault input commits exactly the derived compute budget ${expectedVaultBudget} for ${manifest.action.sdkAction}`);
  }

  /* AUTHORITY: an owner path must carry exactly one input of the pinned root
   * family; a delegate spend must carry NONE. */
  const rootIns = inputs.filter((i) => i.utxo.covenantId === manifest.vault.orgRootCovenantId);
  const rootOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.orgRootCovenantId);
  if (manifest.action.sdkAction === "agentSpend") {
    check(`${tag}agentPathHasNoRoot`, rootIns.length === 0 && rootOuts.length === 0 && manifest.action.requiresRootInput === false, "a delegate spend never touches the organizational root");
  } else {
    const authority = ownGet(ROOTED_KAS_VAULT_ACTIONS, manifest.action.sdkAction) ? resolveOwnerOpAuthorityV7Kas(manifest.action.sdkAction) : null;
    check(`${tag}rootAuthorityPresent`, rootIns.length === 1 && rootOuts.length === 1 && manifest.action.requiresRootInput === true, "exactly one pinned root input and continuation output");
    check(
      `${tag}rootAuthorityPath`,
      !!authority && authority.rootActionName === manifest.action.requiredRootAction && authority.expectFrozenAfter.toString() === manifest.action.expectFrozenAfter && (authority.opSelector === null || authority.opSelector === manifest.action.opSelector),
      `${manifest.action.sdkAction} requires the root to run ${authority ? authority.rootActionName : "?"}`
    );
  }

  if (info.terminal) {
    const selfOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.covenantId);
    check(`${tag}terminalNoContinuation`, selfOuts.length === 0, "a terminal operation leaves no continuation of its own covenant"); // rc21 review R6-03 (ported from v7)
  }
  if (!info.terminal) {
    const after = normalizeStateV4(manifest.stateAfter.state);
    const succ = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.covenantId);
    check(
      `${tag}successorOutput`,
      succ.length === 1 && succ[0].value === (after.protectedValue + after.feeReserve).toString(),
      "exactly one successor carrying protectedValue + feeReserve"
    );

    /* R7-04 closure: the SUCCESSOR LOCKING SCRIPT is rebuilt from the bound predecessor redeem (its template around the
     * reviewed successor state) AND from the declared pins; the successor output must carry exactly its P2SH — a
     * substituted continuation script with the right value and covenant metadata is refused here, before signing. */
    const outSpk = succ.length === 1 && succ[0].scriptPublicKey ? succ[0].scriptPublicKey : {};
    if (parts) {
      let expectedSuccessorSpk = null, rebuildError = null;
      try { expectedSuccessorSpk = vaultScriptV7Kas.reconstructVaultSuccessorSpkHexV7Kas({ redeemHex, vaultId: manifest.vault.vaultId, state: manifest.stateAfter.state }); } catch (e) { rebuildError = e && e.message ? e.message : String(e); }
      check(`${tag}successorScriptReconstructed`, rebuildError === null && Number(outSpk.version || 0) === 0 && String(outSpk.scriptHex || "").toLowerCase() === expectedSuccessorSpk, rebuildError ? `the successor script could not be rebuilt from the reviewed successor state: ${rebuildError}` : "the successor output carries exactly the P2SH of the predecessor's template around the reviewed successor state");
    }
    if (pinsBound) {
      let fromPins = null, pinError = null;
      try { fromPins = vaultScriptV7Kas.reconstructVaultScriptSpkHexV7Kas({ template: vaultScriptV7Kas.templatePinsFromManifestVaultV7Kas(manifest.vault), state: manifest.stateAfter.state }); } catch (e) { pinError = e && e.message ? e.message : String(e); }
      check(`${tag}successorScriptFromPins`, pinError === null && Number(outSpk.version || 0) === 0 && String(outSpk.scriptHex || "").toLowerCase() === fromPins, pinError ? `the successor script could not be rebuilt from the declared pins: ${pinError}` : "the successor output is exactly the v0.7-kas script rebuilt from the declared pins around the reviewed successor state");
    }
    if (manifest.action.sdkAction !== "agentSpend") {
      const sel = manifest.action.opSelector;
      check(`${tag}selectorEffect`, selectorEffectHoldsV7Kas(sel, before, after), `selector ${sel} moves exactly the fields its covenant branch allows`);
      if (manifest.action.sdkAction === "ownerSetAgentRoot") {
        /* rc26 round-7 review R7-02 (parity): the installed root is DERIVED from the carried policy set (v4 leaf layout). */
        const set = manifest.policy && Array.isArray(manifest.policy.agentSet) ? manifest.policy.agentSet : null;
        check(`${tag}agentSetPresent`, set !== null, "the new delegate policy set is carried by the manifest — the owners approve the RULES, never a bare root");
        if (set !== null) {
          let foldError = null;
          let foldRoot = null;
          /* Codex checkpoint 11 (R7-02, recipients): every carried policy lists its COMPLETE recipient set and its
         * agentRecipientRoot must be exactly the fold of those recipients — withheld, emptied, substituted or extended
         * recipients, or a root that does not match them, refuse here. The agent tree folds from the POLICY fields. */
        let recipientsError = null;
        set.forEach((p, i) => {
          if (recipientsError !== null) return;
          if (!p || typeof p !== "object") { recipientsError = `agentSet[${i}] is not an object`; return; }
          if (!Array.isArray(p.recipients) || p.recipients.length === 0) { recipientsError = `agentSet[${i}] carries no recipient set — the owners must see every destination this delegate may pay`; return; }
          let root = null;
          try { root = buildRecipientTree(p.recipients).root; } catch (e) { recipientsError = `agentSet[${i}].recipients: ${e.message}`; return; }
          if (typeof p.agentRecipientRoot !== "string" || p.agentRecipientRoot.toLowerCase() !== root) recipientsError = `agentSet[${i}].agentRecipientRoot ${String(p.agentRecipientRoot).slice(0, 16)}… is not the Merkle root of its ${p.recipients.length} recipient(s) (${root.slice(0, 16)}…)`;
        });
        check(`${tag}agentRecipientsBound`, recipientsError === null, recipientsError ?? "every carried policy's agentRecipientRoot is the Merkle root of its listed recipients");
        try { foldRoot = buildAgentTreeV4(set.map((p) => { const { recipients, ...policy } = p || {}; void recipients; return policy; })).root; } catch (e) { foldError = e.message; }
          check(`${tag}agentSetBound`, foldError === null && foldRoot === after.agentRoot, foldError ? `the carried policy set is malformed: ${foldError}` : `stateAfter.agentRoot ${after.agentRoot} must be the Merkle root of the carried policy set (${foldRoot})`);
        }
      }
    }
  }

  if (manifest.action.sdkAction === "agentSpend") {
    check(`${tag}outputZeroIsRecipient`, outputs[0].scriptPublicKey.scriptHex.toLowerCase() === `20${manifest.policy.recipient}ac`, "the covenant binds the payment to output 0 (P2PK recipient)");
    const policy = manifest.policy.agentPolicy ? normalizeAgentPolicyV4(manifest.policy.agentPolicy) : null;
    check(`${tag}agentPolicyPresent`, !!policy, "agent policy carried");
    if (policy) {
      const proof = manifest.policy.agentProof;
      check(`${tag}agentProof`, !!proof && verifyAgentProofV4({ root: before.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) }), "leaf proven under the predecessor agentRoot");
      const after = normalizeStateV4(manifest.stateAfter.state);
      const spend = digits(outputs[0].value, "outputs[0].value");
      check(`${tag}spendWithinCap`, spend <= policy.maxPerSpend, `spend ${spend} <= cap ${policy.maxPerSpend}`);
      const periods = digits(manifest.policy.periodsElapsed, "policy.periodsElapsed");
      const newStart = periods >= 1n ? policy.periodStartDaa + periods * policy.periodLengthDaa : policy.periodStartDaa;
      const newSpent = periods >= 1n ? spend : policy.periodSpent + spend;
      check(`${tag}spendWithinBudget`, newSpent <= policy.periodBudget, `period spent ${newSpent} <= budget ${policy.periodBudget}`);
      const expectedLockTime = periods >= 1n ? newStart : 0n;
      check(
        `${tag}lockTimeBound`,
        digits(manifest.policy.lockTime, "policy.lockTime") === BigInt(frozen.lockTime) && BigInt(frozen.lockTime) === expectedLockTime,
        `lockTime must be exactly ${expectedLockTime} for periodsElapsed ${periods} (declared ${manifest.policy.lockTime}, frozen ${frozen.lockTime})`
      );
      check(`${tag}successorRootDerived`, foldAgentPolicyV4({ ...policy, periodStartDaa: newStart, periodSpent: newSpent }, proof.siblingsHex, BigInt(proof.pathBits)) === after.agentRoot, "successor agentRoot == single-leaf fold of the advanced leaf");
      check(`${tag}reserveWithinAgentCap`, digits(manifest.accounting.kas.reserveConsumed, "accounting.kas.reserveConsumed") <= policy.agentMaxFeePerTx, "reserve consumed <= agentMaxFeePerTx");
      const rp = manifest.policy.recipientProof;
      check(`${tag}recipientAllowlisted`, !!rp && rp.root === policy.agentRecipientRoot && verifyRecipientProof({ root: rp.root, recipient: manifest.policy.recipient, siblingsHex: rp.siblingsHex, pathBits: BigInt(rp.pathBits) }), "recipient proven under the agent's recipient root");
      /* the vault-level M-of-N approver tier, shown honestly (counts + keys,
       * never raw signatures) and cross-checked against the DECLARED
       * threshold — this is NOT the organizational root's quorum. */
      const at = manifest.approverTier;
      check(`${tag}approverTierPresent`, !!at, "the vault-level approver tier is declared");
      if (at) {
        check(`${tag}approverTierThresholdMatchesLeaf`, at.approvalThreshold === manifest.policy.agentPolicy.approvalThreshold, "the declared threshold matches the leaf's own approvalThreshold");
        check(`${tag}approverTierAboveThresholdFlag`, at.aboveThreshold === spend > digits(at.approvalThreshold, "approverTier.approvalThreshold"), "aboveThreshold reflects spend vs the leaf threshold");
        if (at.aboveThreshold) check(`${tag}approverTierRequiresM`, BigInt(at.requiredM) >= 1n && BigInt(at.requiredM) <= BigInt(at.activeApprovers.length), "an above-threshold spend needs a well-formed approver tier (M in [1, activeCount])");
      }
    }
  } else if (manifest.action.sdkAction === "ownerRecover") {
    check(
      `${tag}payoutToPinnedRecoveryPk`,
      redeemPins !== null && String(manifest.vault.recoveryPk).toLowerCase() === redeemPins.recoveryPk && outputs[0].scriptPublicKey.scriptHex.toLowerCase() === `20${redeemPins.recoveryPk}ac` && outputs[0].value === (before.protectedValue + before.feeReserve).toString() && outputs[0].value === manifest.accounting.kas.terminalPayout,
      "output 0 pays protectedValue + feeReserve to the recoveryPk COMPILED INTO the spent vault's script (decoded from the bound redeem — R7-04), which must equal the declared genesis pin"
    );
  }
}

/* ------------------------------------------------------------------ */
/* the ORGANIZATIONAL ROOT (KAS-vault) manifest                        */
/* ------------------------------------------------------------------ */

/* `build` is either a root-only build (kind "orgRootTransition") or a
 * rooted-KAS-vault build whose `rootAuthority` describes the root side —
 * IDENTICAL shape to the payment profile's (finishBuildV7Kas produces the
 * SAME rootAuthority fields finishBuild in vault-builders-v7.js does), so
 * this is restated here (not imported) only because the payment profile's
 * own wrapper hard-wires its vaultOperations loop. */
function rootFactsFrom(build) {
  if (build.kind === "orgRootTransition") {
    const action = resolveRootActionV7(build.action);
    return {
      covenantId: build.covenantId,
      outpoint: build.predecessorOutpoint,
      template: build.template,
      prevState: build.stateJson,
      newState: build.successorState,
      prevDigest: build.predecessorStateDigest,
      newDigest: build.successorStateDigest,
      tailHex: build.successorTailHex,
      actionName: build.action,
      actionCode: action.action,
      entrypoint: action.entrypoint,
      class: action.class,
      classForPreviousSet: action.classForPreviousSet ?? null,
      quorumSource: build.quorumSource,
      requiredApprovals: build.requiredApprovals,
      expectedSignerSlots: build.expectedSignerSlots,
      minSequence: build.minSequence,
      valueBefore: build.accounting.kas.rootValueBefore,
      valueAfter: build.accounting.kas.rootValueAfter,
      rootMaxFeePerTx: build.accounting.kas.rootMaxFeePerTx,
      computeBudget: build.computeBudget
    };
  }
  const ra = build.rootAuthority;
  if (!ra) refuse("SCHEMA_INVALID", "a rooted-kas-vault build without a root input cannot carry an organizational-root manifest");
  const action = resolveRootActionV7(ra.rootActionName);
  return {
    covenantId: ra.covenantId,
    outpoint: ra.outpoint,
    template: ra.template,
    prevState: ra.prevState,
    newState: ra.newState,
    prevDigest: ra.prevStateDigest,
    newDigest: ra.newStateDigest,
    tailHex: ra.successorTailHex,
    actionName: ra.rootActionName,
    actionCode: action.action,
    entrypoint: action.entrypoint,
    class: action.class,
    classForPreviousSet: action.classForPreviousSet ?? null,
    quorumSource: ra.quorumSource,
    requiredApprovals: ra.requiredApprovals,
    expectedSignerSlots: ra.expectedSignerSlots,
    minSequence: "0",
    valueBefore: ra.value,
    valueAfter: ra.value,
    rootMaxFeePerTx: normalizeRootTemplateV7(ra.template).rootMaxFeePerTx.toString(),
    computeBudget: ra.computeBudget
  };
}

function setSummary(stateJson) {
  const s = normalizeRootStateV7(stateJson);
  return {
    activeCount: s.activeCount,
    ownerM: s.ownerM.toString(),
    emergencyK: s.emergencyK.toString(),
    recoveryM: s.recoveryM.toString(),
    slots: activeOwnerSlotsV7(s).map((x) => ({ slot: x.slot, publicKey: x.publicKey }))
  };
}

function buildOrgRootIntentManifestV7Kas({ build, vaultOperations = [], satisfiedApprovals = null }) {
  if (!build || typeof build !== "object") refuse("SCHEMA_INVALID", "a v0.7 build is required");
  const facts = rootFactsFrom(build);
  const before = setSummary(facts.prevState);
  const after = setSummary(facts.newState);
  const beforeKeys = new Set(before.slots.map((s) => s.publicKey));
  const afterKeys = new Set(after.slots.map((s) => s.publicKey));

  const ops = vaultOperations.map((op) => {
    const m = buildRootedKasVaultManifestV7({ build: op.build });
    return {
      covenantId: op.build.covenantId,
      vaultId: op.build.template.vaultId,
      sdkAction: op.build.action,
      opSelector: op.build.callExtra.opSelector ?? null,
      terminal: ownGet(ROOTED_KAS_VAULT_ACTIONS, op.build.action).terminal,
      manifest: m
    };
  });

  const body = {
    manifestVersion: ORG_ROOT_KAS_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    root: {
      contractVersion: "policyvault-0.7-root",
      orgId: normalizeRootStateV7(facts.prevState).boundOrgId,
      covenantId: facts.covenantId,
      outpoint: facts.outpoint,
      template: {
        recoveryDelayDaa: normalizeRootTemplateV7(facts.template).recoveryDelayDaa.toString(),
        successorPk: normalizeRootTemplateV7(facts.template).successorPk,
        successionEnabled: normalizeRootTemplateV7(facts.template).successionEnabled,
        successionDelayDaa: normalizeRootTemplateV7(facts.template).successionDelayDaa.toString(),
        rootMaxFeePerTx: facts.rootMaxFeePerTx
      },
      valueBefore: facts.valueBefore,
      valueAfter: facts.valueAfter,
      computeBudget: facts.computeBudget
    },
    action: {
      name: facts.actionName,
      code: facts.actionCode,
      entrypoint: facts.entrypoint,
      authorityClass: facts.class,
      authorityClassForPreviousSet: facts.classForPreviousSet,
      quorumSource: facts.quorumSource,
      requiredApprovals: facts.requiredApprovals,
      satisfiedApprovals: satisfiedApprovals === null ? null : String(satisfiedApprovals),
      expectedSignerSlots: facts.expectedSignerSlots.map((s) => ({ slot: s.slot, publicKey: s.publicKey })),
      minSequence: facts.minSequence
    },
    ownerSet: {
      before,
      after,
      changes: {
        added: after.slots.filter((s) => !beforeKeys.has(s.publicKey)).map((s) => s.publicKey),
        removed: before.slots.filter((s) => !afterKeys.has(s.publicKey)).map((s) => s.publicKey),
        thresholdsChanged: before.ownerM !== after.ownerM || before.emergencyK !== after.emergencyK || before.recoveryM !== after.recoveryM,
        frozenChanged: normalizeRootStateV7(facts.prevState).frozen !== normalizeRootStateV7(facts.newState).frozen
      }
    },
    rootState: {
      before: { digest: facts.prevDigest, state: rootStateToJsonV7(normalizeRootStateV7(facts.prevState)) },
      after: { digest: facts.newDigest, state: rootStateToJsonV7(normalizeRootStateV7(facts.newState)), tailHex: facts.tailHex }
    },
    vaultOperations: ops,
    fee: {
      requiredFeeSompi: build.requiredFeeSompi,
      rootMaxFeePerTx: facts.rootMaxFeePerTx,
      rootValueLoss: (BigInt(facts.valueBefore) - BigInt(facts.valueAfter)).toString()
    },
    freshness: {
      kind: "ROOT_OUTPOINT_KILL_SWITCH",
      rootOutpoint: facts.outpoint,
      expiry: null,
      note: "Approvals are bound to this root outpoint and to this exact transaction (SIGHASH_ALL). Spending the outpoint invalidates every collected approval; the root nonce strictly increases. There is deliberately no expiry: Kaspa lockTime is a lower bound only."
    },
    transaction: { txId: build.txId, frozenCanonicalJson: build.frozenCanonicalJson },
    explanation: ORG_ROOT_KAS_EXPLANATION
  };
  return deepFreeze({ ...body, manifestHash: computeManifestHashV1(body) });
}

function verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts = {} }) {
  const checks = [];
  const failures = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail ?? null });
    if (!ok) failures.push({ name, detail: detail ?? null });
  };
  try {
    if (manifest.manifestVersion !== ORG_ROOT_KAS_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown org-root-kas manifest version — failing closed");
    const { manifestHash, ...body } = manifest;
    check("manifestHash", computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
    check("explanationVerbatim", manifest.explanation === ORG_ROOT_KAS_EXPLANATION, "the fixed human explanation is carried verbatim");
    check("freshnessIsOutpointKillSwitch", manifest.freshness.kind === "ROOT_OUTPOINT_KILL_SWITCH" && manifest.freshness.expiry === null, "freshness is the root outpoint, never an expiry");

    const action = resolveRootActionV7(manifest.action.name);
    check("actionTable", action.action === manifest.action.code && action.entrypoint === manifest.action.entrypoint && action.class === manifest.action.authorityClass && action.quorumSource === manifest.action.quorumSource, "action / class / entrypoint / quorum source come from the action table");

    const before = normalizeRootStateV7(manifest.rootState.before.state);
    const after = normalizeRootStateV7(manifest.rootState.after.state);
    check("stateDigests", computeRootStateDigestV7(before) === manifest.rootState.before.digest && computeRootStateDigestV7(after) === manifest.rootState.after.digest, "both digests recomputed from the exact 467-byte state regions");
    check("orgIdBound", before.boundOrgId === after.boundOrgId && before.boundOrgId === manifest.root.orgId, "the bound organization id is immutable");
    check("nonceAdvancesByOne", after.rootNonce === before.rootNonce + 1n, `nonce ${before.rootNonce} -> ${after.rootNonce}`);
    check("successorTailBytes", manifest.rootState.after.tailHex === rootStateTailHexV7({ frozen: after.frozen, rootNonce: after.rootNonce }), "the pinned successor TAIL equals 0x01||frozen||0x08||nonce8");
    if (action.landsFrozen !== null) check("frozenOutcome", after.frozen === action.landsFrozen, `${manifest.action.name} must land frozen=${action.landsFrozen}`);
    else check("frozenPreserved", after.frozen === before.frozen, `${manifest.action.name} preserves the frozen flag`);
    if (action.requiresUnfrozen) check("rootNotFrozen", before.frozen === 0n, "the predecessor must be unfrozen for this action");
    const setPreserved = before.owners.every((k, i) => k === after.owners[i]) && before.ownerM === after.ownerM && before.emergencyK === after.emergencyK && before.recoveryM === after.recoveryM;
    if (action.setMayChange) check("setChangeDeclared", true, "this action may install a new set");
    else check("setPreserved", setPreserved, `${manifest.action.name} must carry the owner set across verbatim`);
    check("ownerSetSummaries", manifest.ownerSet.before.ownerM === before.ownerM.toString() && manifest.ownerSet.after.ownerM === after.ownerM.toString() && manifest.ownerSet.before.activeCount === before.activeCount && manifest.ownerSet.after.activeCount === after.activeCount, "the declared summaries match the declared states");
    const declaredAdded = new Set(manifest.ownerSet.changes.added);
    const actualAdded = activeOwnerSlotsV7(after).map((s) => s.publicKey).filter((k) => !activeOwnerSlotsV7(before).some((b) => b.publicKey === k));
    check("ownerSetDiff", actualAdded.length === declaredAdded.size && actualAdded.every((k) => declaredAdded.has(k)), "the declared owner-set diff is the real one");

    const required = requiredApprovalsV7(before, manifest.action.name);
    check("requiredApprovals", required.toString() === manifest.action.requiredApprovals, `${manifest.action.name} requires ${required} from the PREDECESSOR set`);
    const expected = manifest.action.name === "succession" ? [] : activeOwnerSlotsV7(before).map((s) => `${s.slot}:${s.publicKey}`);
    check("expectedSignerSlots", JSON.stringify(manifest.action.expectedSignerSlots.map((s) => `${s.slot}:${s.publicKey}`)) === JSON.stringify(expected), "the expected signer slots are exactly the predecessor's active slots");
    if (manifest.action.satisfiedApprovals !== null) {
      check("quorumSatisfied", digits(manifest.action.satisfiedApprovals, "action.satisfiedApprovals") >= required, "the collected approvals reach the required threshold");
    }
    if (action.requiresAge) {
      const t = normalizeRootTemplateV7({ ...manifest.root.template, orgId: manifest.root.orgId });
      const expectedSeq = manifest.action.name === "succession" ? t.successionDelayDaa : t.recoveryDelayDaa;
      check("relativeAgeGate", digits(manifest.action.minSequence, "action.minSequence") === expectedSeq, `the input sequence must carry the ${manifest.action.name} idle delay`);
    }

    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const inputs = frozen.inputs;
    const outputs = frozen.outputs;
    const totalIn = inputs.reduce((s, i) => s + BigInt(i.utxo.amount), 0n);
    const totalOut = outputs.reduce((s, o) => s + BigInt(o.value), 0n);
    const fee = totalIn - totalOut;
    check("feeExact", fee.toString() === manifest.fee.requiredFeeSompi, `fee ${fee}`);

    const rootIns = inputs.filter((i) => i.utxo.covenantId === manifest.root.covenantId);
    const rootOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.root.covenantId);
    check("rootInputSingleton", rootIns.length === 1 && rootOuts.length === 1, "exactly one root input and one root continuation output");
    { /* Codex checkpoint 6 (UX-02 / UX-13), ported from the payment verifier: derived root + ordinary input budgets */
      let expectedRootBudget = null, rootBudgetError = null;
      try { expectedRootBudget = selectRootComputeBudgetV7({ actionName: manifest.action.name, activeOwnerSlots: before.activeCount }); } catch (e) { rootBudgetError = e && e.message ? e.message : String(e); }
      check("rootComputeBudgetBound", rootBudgetError === null && rootIns.length === 1 && Number.isInteger(rootIns[0].computeBudget) && rootIns[0].computeBudget === expectedRootBudget && String(manifest.root.computeBudget) === String(expectedRootBudget), rootBudgetError ? `the root input's compute budget could not be derived: ${rootBudgetError}` : `the root input commits exactly the derived compute budget ${expectedRootBudget} for ${manifest.action.name} with ${before.activeCount} active slot(s)`);
      const plain = inputs.filter((i) => i.utxo.covenantId === null || i.utxo.covenantId === undefined);
      check("ordinaryInputBudgets", plain.every((i) => Number.isInteger(i.computeBudget) && i.computeBudget === V7_KAS_BUDGET.ORDINARY_INPUT), `every plain input commits the ordinary compute budget ${V7_KAS_BUDGET.ORDINARY_INPUT}`);
    }
    /* rc21 review R6-03: the five rc21 outer checks of the v7 verifier, ported to this profile (same frozen v0.7 root). */
    let rootEvidence = null; // Codex checkpoint 7: the rebuilt root script's REAL geometry + in-VM template identity
    if (rootIns.length === 1 && rootOuts.length === 1) {
      let expectBefore = null, expectAfter = null, rebuildError = null;
      try {
        const tpl = { ...manifest.root.template, orgId: manifest.root.orgId };
        const rootBeforeHex = rootScriptV7.reconstructRootScriptHexV7({ template: tpl, state: manifest.rootState.before.state });
        expectBefore = rootScriptV7.p2shSpkHexOf(rootBeforeHex);
        expectAfter = rootScriptV7.p2shSpkHexOf(rootScriptV7.reconstructRootScriptHexV7({ template: tpl, state: manifest.rootState.after.state }));
        const prefixHex = rootBeforeHex.slice(0, rootScriptV7.ROOT_SCRIPT_PREFIX_HEX_V7.length);
        const suffixHex = rootBeforeHex.slice(rootScriptV7.ROOT_SCRIPT_PREFIX_HEX_V7.length + ROOT_STATE_LEN_V7 * 2);
        rootEvidence = { prefixLen: prefixHex.length / 2, stateLen: ROOT_STATE_LEN_V7, suffixLen: suffixHex.length / 2, templateVmHash: blake2bHex([hexToBytes(prefixHex), hexToBytes(suffixHex)], 32) }; // Codex checkpoint 7 (parity with the payment profile)
      } catch (e) { rebuildError = e && e.message ? e.message : String(e); }
      const inSpk = rootIns[0].utxo.scriptPublicKey || {};
      const outSpk = rootOuts[0].scriptPublicKey || {};
      check("rootScriptsBound", rebuildError === null && Number(inSpk.version || 0) === 0 && String(inSpk.scriptHex || "").toLowerCase() === expectBefore && Number(outSpk.version || 0) === 0 && String(outSpk.scriptHex || "").toLowerCase() === expectAfter, rebuildError ? `the root script could not be rebuilt from the reviewed template and state: ${rebuildError}` : "the root input spends, and the root output creates, exactly the P2SH of the frozen v0.7 root script rebuilt from the reviewed template and states");
    }
    const continuations = new Map();
    let genesisShaped = 0;
    for (const o of outputs) {
      if (!o.covenant) continue;
      const ai = Number(o.covenant.authorizingInput);
      const src = Number.isInteger(ai) && inputs[ai] ? inputs[ai].utxo.covenantId : null;
      if (src === null || src === undefined || String(src).toLowerCase() !== String(o.covenant.covenantId).toLowerCase()) genesisShaped += 1;
      else continuations.set(ai, (continuations.get(ai) || 0) + 1);
    }
    check("noCovenantGenesisInRootAction", genesisShaped === 0, genesisShaped ? `${genesisShaped} covenant output(s) do not continue the covenant of the input they name (a root action never creates a covenant)` : "every covenant output continues the covenant of the input it names");
    check("oneContinuationPerCovenantInput", [...continuations.values()].every((n) => n === 1), "each covenant input continues at most once");
    {
      const spk = String(manifest.root.template.successorPk || "").toLowerCase();
      const on = /^[0-9a-f]{64}$/.test(spk) && spk !== "00".repeat(32);
      check("successionFlag", manifest.root.template.successionEnabled === on, `template.successionEnabled must be ${on} for successorPk ${spk.slice(0, 8)}…`);
    }
    {
      const fuelSpk = inputs.length ? String(inputs[inputs.length - 1].utxo.scriptPublicKey.scriptHex || "").toLowerCase() : "";
      const fuelOk = /^20[0-9a-f]{64}ac$/.test(fuelSpk) && inputs[inputs.length - 1].utxo.covenantId === null;
      const terminalOps = manifest.vaultOperations.filter((op) => op.manifest && op.manifest.action && op.manifest.action.terminal === true);
      const payoutSpks = new Set(terminalOps.map((op) => `20${String((op.manifest.vault && op.manifest.vault.recoveryPk) || "").toLowerCase()}ac`));
      let change = 0, payouts = 0, bad = 0;
      outputs.forEach((o, n) => {
        if (o.covenant) return;
        const spk = String(o.scriptPublicKey.scriptHex || "").toLowerCase();
        if (n === 0 && terminalOps.length === 1 && payoutSpks.has(spk)) { payouts += 1; return; }
        if (fuelOk && spk === fuelSpk) { change += 1; return; }
        bad += 1;
      });
      check("feePayerChangeBound", fuelOk && bad === 0 && change <= 1 && terminalOps.length <= 1 && payouts === terminalOps.length, `non-covenant outputs: ${payouts} payout(s) for ${terminalOps.length} terminal operation(s), ${change} change output(s) to the fee payer, ${bad} other destination(s)`);
    }
    if (rootIns.length === 1) {
      check("rootOutpointBinding", rootIns[0].previousOutpoint.transactionId === manifest.root.outpoint.transactionId && Number(rootIns[0].previousOutpoint.index) === Number(manifest.root.outpoint.index) && rootIns[0].previousOutpoint.transactionId === manifest.freshness.rootOutpoint.transactionId, "the declared root outpoint IS the spent one (the freshness kill switch)");
      check("rootValueBefore", rootIns[0].utxo.amount === manifest.root.valueBefore, "the declared root value is the input's");
      if (action.requiresAge) check("rootInputSequence", String(rootIns[0].sequence) === manifest.action.minSequence, "the root input carries the relative-age sequence");
      else check("rootInputSequenceZero", String(rootIns[0].sequence) === "0", `${manifest.action.name} is not age-gated: the root input must carry sequence 0 (a non-zero sequence is a hidden relative lock)`); // rc26 round-7 review R7-01
    }
    /* rc26 round-7 review R7-01 (parity): no other input carries a sequence; a root transaction never carries a lockTime. */
    check("inputSequencesZero", inputs.every((i) => i.utxo.covenantId === manifest.root.covenantId || String(i.sequence) === "0"), "every non-root input carries sequence 0 — no hidden relative lock");
    check("lockTimeZero", String(frozen.lockTime) === "0", `a root transaction never carries a lock time (frozen lockTime ${frozen.lockTime})`);
    if (rootOuts.length === 1) {
      check("rootValueAfter", rootOuts[0].value === manifest.root.valueAfter, "the declared successor value is the output's");
      const loss = BigInt(manifest.root.valueBefore) - BigInt(rootOuts[0].value);
      check("rootValueRule", loss <= digits(manifest.root.template.rootMaxFeePerTx, "root.template.rootMaxFeePerTx") && loss.toString() === manifest.fee.rootValueLoss, `the root loses ${loss} <= rootMaxFeePerTx ${manifest.root.template.rootMaxFeePerTx}`);
    }

    const accounted = new Set([manifest.root.covenantId]);
    for (const op of manifest.vaultOperations) {
      check(`vaultOp[${String(op.covenantId).slice(0, 8)}]idsBound`, op.manifest && op.manifest.vault && op.covenantId === op.manifest.vault.covenantId && (op.tokenCovenantId ?? null) === (op.manifest.vault.tokenCovenantId ?? null), "the declared vault covenant id is the inner manifest's"); // rc21 review R6-03
      accounted.add(op.covenantId);
      check(`vaultOp[${op.covenantId.slice(0, 8)}]declared`, inputs.some((i) => i.utxo.covenantId === op.covenantId), "the declared vault operation has an input in this transaction");
      check(`vaultOp[${op.covenantId.slice(0, 8)}]rootPin`, op.manifest.vault.orgRootCovenantId === manifest.root.covenantId, "the vault is pinned to THIS root");
      { /* Codex checkpoint 7 (UX-02 / UX-13, parity with the payment profile): the vault's declared root geometry + root template hash must be the rebuilt root script's */
        const g = op.manifest.vault && op.manifest.vault.rootGeometry ? op.manifest.vault.rootGeometry : {};
        const agrees = !!rootEvidence && Number(g.prefixLen) === rootEvidence.prefixLen && Number(g.stateLen) === rootEvidence.stateLen && Number(g.suffixLen) === rootEvidence.suffixLen && String(op.manifest.vault.rootTemplateVmHash || "").toLowerCase() === rootEvidence.templateVmHash;
        check(`vaultOp[${op.covenantId.slice(0, 8)}]rootEvidenceAgrees`, agrees, rootEvidence ? `the vault's declared root geometry (${g.prefixLen} / ${g.stateLen} / ${g.suffixLen}) and root template hash must be the rebuilt root script's (${rootEvidence.prefixLen} / ${rootEvidence.stateLen} / ${rootEvidence.suffixLen}, ${rootEvidence.templateVmHash.slice(0, 8)}…)` : "the root script could not be rebuilt, so the vault's root pins cannot be bound");
      }
      if (op.manifest.action.requiresRootInput) {
        check(
          `vaultOp[${op.covenantId.slice(0, 8)}]rootPathAgreesWithThisManifest`,
          op.manifest.action.requiredRootAction === manifest.action.name,
          `${op.manifest.action.sdkAction} requires the root to run ${op.manifest.action.requiredRootAction}, and this manifest runs ${manifest.action.name}`
        );
        const landsFrozen = action.landsFrozen === null ? before.frozen : action.landsFrozen;
        check(
          `vaultOp[${op.covenantId.slice(0, 8)}]frozenByteAgrees`,
          digits(op.manifest.action.expectFrozenAfter, "expectFrozenAfter") === landsFrozen,
          "the frozen byte the vault pins in the root's successor is the one this action produces"
        );
      }
      /* R7-04 closure: the caller supplies the vault's predecessor redeem (keyed by covenantId, own-property lookup); absent => the op is REFUSED, never assumed */
      const redeemHex = redeemScripts && typeof redeemScripts === "object" && !Array.isArray(redeemScripts) ? (ownGet(redeemScripts, op.covenantId) ?? null) : null;
      verifyRootedKasVaultManifestV7({ manifest: op.manifest, frozen, redeemHex, check });
    }
    const unaccounted = inputs.map((i) => i.utxo.covenantId).filter((c) => c !== null && !accounted.has(c));
    check("noHiddenCovenantOperations", unaccounted.length === 0, unaccounted.length ? `undeclared covenant families among the inputs: ${[...new Set(unaccounted)].join(", ")}` : "every covenant input is accounted for by a declared operation");
    const unaccountedOut = outputs.filter((o) => o.covenant && !accounted.has(o.covenant.covenantId));
    check("noHiddenCovenantOutputs", unaccountedOut.length === 0, "every covenant output is accounted for by a declared operation");
    check("txIdDeclared", typeof manifest.transaction.txId === "string" && /^[0-9a-f]{64}$/.test(manifest.transaction.txId), "the transaction id is well-formed");
  } catch (e) {
    failures.push({ name: "exception", detail: `${e.code ?? "ERROR"}: ${e.message}` });
    checks.push({ name: "exception", ok: false, detail: `${e.code ?? "ERROR"}: ${e.message}` });
  }
  const verdict = failures.length === 0 ? "VERIFIED" : "REFUSED";
  return deepFreeze({ verdict, statement: verdict === "VERIFIED" ? VERIFIED_STATEMENT : null, checks, failures, manifestHash: manifest.manifestHash ?? null });
}

module.exports = {
  ORG_ROOT_KAS_MANIFEST_VERSION_1,
  ROOTED_KAS_VAULT_MANIFEST_VERSION_1,
  ORG_ROOT_KAS_EXPLANATION,
  ROOTED_KAS_VAULT_ACTIONS,
  VERIFIED_STATEMENT,
  buildOrgRootIntentManifestV7Kas,
  verifyOrgRootIntentManifestV7Kas,
  buildRootedKasVaultManifestV7,
  verifyRootedKasVaultManifestV7,
  canonicalJsonStringify,
  OWNER_SLOTS_V7,
  normalizeOwnerSetV7,
  normalizeTemplateV7Kas,
  templateToJsonV7Kas,
  stateToJsonV4
};
