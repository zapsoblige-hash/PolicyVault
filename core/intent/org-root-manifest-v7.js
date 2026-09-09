"use strict";

/*
 * policyvault-org-root-manifest/1 — the closed-schema, hash-committed
 * description of ONE frozen v0.7 ORGANIZATIONAL ROOT transaction, plus its
 * deterministic LOCAL VERIFICATION against the frozen transaction bytes.
 * Additive beside the v0.4 intent manifest (core/intent/manifest.js) and the
 * v0.5 token manifest (core/intent/token-manifest-v5.js), both untouched.
 *
 * WHAT A SIGNING OWNER MUST BE ABLE TO SEE, and therefore what this manifest
 * states — and RE-DERIVES rather than trusting:
 *
 *   - WHICH root is being spent (covenant id + the exact outpoint);
 *   - the prev and new root state DIGESTS over the exact consensus-visible
 *     467-byte state regions, so two parties comparing digests are comparing
 *     the bytes consensus compares;
 *   - the ACTION and its authority CLASS (AUTHORITY-REDUCING / -NEUTRAL /
 *     -EXPANDING / TERMINAL-for-the-previous-set);
 *   - the THRESHOLD required and satisfied, and exactly which owner slots are
 *     expected to sign;
 *   - EVERY vault operation riding in the same transaction, each with its own
 *     controller manifest — and a transaction carrying a covenant family that
 *     no declared operation accounts for is REFUSED, so a hidden extra vault
 *     operation cannot be smuggled past a signer;
 *   - the FEE and the bound on how much value the root may lose;
 *   - FRESHNESS: the root's outpoint is the kill switch. There is NO expiry
 *     field, deliberately — Kaspa lockTime is a lower bound only, so a
 *     "valid until" value would be security theatre. Spending the root's
 *     outpoint invalidates every collected approval at once, and the nonce
 *     strictly increases.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/intent/test/org-root-manifest-v7.test.js
 * and sdk/test/org-root-manifest-v7.test.js); the same core codecs the
 * real-engine suites pin are used for every derivation.
 */

const { canonicalJsonStringify, computeManifestHashV1 } = require("./canonical");
const { ownGet } = require("../model/own-get"); // rc12 review R-02: own-property action lookups (prototype keys fail closed)
const assets = require("../assets");
const { kcc20 } = assets;
const {
  normalizeRootStateV7,
  normalizeRootTemplateV7,
  serializeRootStateHexV7,
  computeRootStateDigestV7,
  rootStateToJsonV7,
  rootStateTailHexV7
} = require("../model/vault-state-v7-root");
const { resolveRootActionV7, requiredApprovalsV7, activeOwnerSlotsV7, normalizeOwnerSetV7, OWNER_SLOTS_V7 } = require("../model/owner-set-v7");
const { normalizeStateV7, normalizeTemplateV7, resolveOwnerOpAuthorityV7, OWNER_OP_SELECTOR_V7 } = require("../model/vault-state-v7");
const { normalizeTokenAgentPolicyV5, verifyTokenAgentProofV5, foldTokenAgentPolicyV5, buildTokenAgentTreeV5 } = require("../model/agent-merkle-v5");
const { verifyRecipientProof, buildRecipientTree } = require("../model/recipient-merkle-v3");
const { OWNER_SCHEMES } = require("../model/token-amounts");
const { ROOT_STATE_LEN_V7 } = require("../model/vault-state-v7-root"); // Codex checkpoint 7: the root's real geometry, read off the rebuilt root script
const { blake2bHex } = require("../assets/blake2b"); // Codex checkpoint 7: the root's real in-VM template identity, read off the rebuilt root script
const rootScriptV7 = require("./root-script-v7"); // rc20 review R5-04 / R4-07: the frozen v0.7 root script is REBUILT from the reviewed template + state
const vaultScriptV7 = require("./vault-script-v7"); // Codex checkpoint 6 UX-02/13: the rooted VAULT successor script is rebuilt from the vault's own revealed redeem + the reviewed successor state
const { V7_BUDGET, selectRootComputeBudgetV7, selectComputeBudgetV7, selectTokenInputBudgetV7 } = require("../model/compute-budget-v7"); // Codex checkpoint 6 UX-02/13: every input's committed compute budget is DERIVED from the reviewed operation, never merely compared

const ORG_ROOT_MANIFEST_VERSION_1 = "policyvault-org-root-manifest/1";
const ROOTED_VAULT_MANIFEST_VERSION_1 = "policyvault-rooted-vault-manifest/1";
const VERIFIED_STATEMENT = "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.";

/* The fixed human explanation. It never varies with the transaction, so a
 * reader can learn it once and a tampered manifest cannot reword it. */
const ORG_ROOT_EXPLANATION =
  "This transaction spends your organization's PolicyVault root. The root holds the owner set, " +
  "the approval thresholds, the freeze flag and a strictly increasing nonce; it never pays anyone " +
  "and it can never be dissolved. Approving means: the named action runs, the named owner slots " +
  "must sign, and every vault operation listed below happens in the SAME transaction or none of " +
  "them do. Your approval is bound to this exact transaction and to this exact root outpoint — " +
  "there is no expiry, because spending the root outpoint is what invalidates every collected " +
  "approval at once. A rooted vault has no owner key: this root input IS the owner authority.";

const ROOTED_VAULT_ACTIONS = Object.freeze({
  ownerSetAgentRoot: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-EXPANDING" }),
  ownerTopUpReserve: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-NEUTRAL" }),
  ownerPause: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-REDUCING" }),
  ownerUnpause: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-EXPANDING" }),
  ownerEmergencyPause: Object.freeze({ role: "owners", terminal: false, mutationClass: "AUTHORITY-REDUCING" }),
  ownerRecover: Object.freeze({ role: "owners", terminal: true, mutationClass: "TERMINAL" }),
  tokenAgentSpend: Object.freeze({ role: "agent", terminal: false, mutationClass: "AUTHORITY-NEUTRAL" })
});

function refuse(code, message) {
  const e = new Error(message);
  e.code = code;
  throw e;
}
function hex(v, bytes, where) {
  if (typeof v !== "string" || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(v)) refuse("SCHEMA_INVALID", `${where} must be ${bytes}-byte lowercase hex`);
  return v;
}
function digits(v, where) {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) refuse("SCHEMA_INVALID", `${where} must be a non-negative digit string`);
  return BigInt(v);
}
function hexToBytes(hex) { const out = new Uint8Array(hex.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16); return out; }

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* the ROOTED VAULT controller manifest (one vault operation)          */
/* ------------------------------------------------------------------ */

/* Wave 2 Track D (hierarchical delegation): the HD vault's OWNER operations
 * (ownerControl 0-4 / ownerRecover) are byte-identical in substance to
 * v0.7-payment's — same field shapes, same ROOTED_VAULT_ACTIONS entries, no
 * tokenAgentSpend equivalent — so they are presented and verified through
 * THIS SAME manifest family "like the payment profile" (Wave 2 Track D task
 * packet), rather than duplicating ~150 lines of security-critical
 * verification logic. The HD vault's five HD-specific entrypoints
 * (hdSpend/childSpendL2/childSpendL3/delegateSetChildRoot1/2) have their OWN
 * STANDALONE-verifiable manifest family,
 * core/intent/org-root-manifest-v7-hd.js's
 * "policyvault-rooted-hd-vault-manifest/1" — they never ride inside an
 * org-root manifest because they never touch the root. */
const HD_CONTRACT_VERSION = "policyvault-0.7-payment-hd";

function buildRootedVaultManifestV7({ build, descriptor = null }) {
  const isHd = build && build.contractVersion === HD_CONTRACT_VERSION;
  const expectedKind = isHd ? "hdOwnerTransition" : "transition"; /* an HD owner-op build carries a DISTINCT kind from its payment-profile sibling — never "transition" — so the two can never be cross-routed here by accident */
  if (!build || (build.contractVersion !== "policyvault-0.7-payment" && !isHd) || build.kind !== expectedKind) {
    refuse("SCHEMA_INVALID", "a v0.7-payment transition build or a v0.7-payment-hd hdOwnerTransition build is required");
  }
  if (isHd && build.action === "tokenAgentSpend") {
    refuse("SCHEMA_INVALID", "the HD vault has no tokenAgentSpend entrypoint — only owner operations ride inside the org-root manifest; failing closed");
  }
  const info = ownGet(ROOTED_VAULT_ACTIONS, build.action);
  if (!info) refuse("UNKNOWN_ACTION", `unknown v0.7 rooted-vault action ${JSON.stringify(build.action)} — failing closed`);
  let validated = null;
  if (descriptor) {
    validated = assets.validateAssetDescriptor(descriptor);
    if (assets.computeDescriptorHash(validated) !== build.template.descriptorHash) refuse("DESCRIPTOR_PIN_MISMATCH", "descriptor hash != the vault's pinned descriptorHash");
  }
  const authority = build.action === "tokenAgentSpend" ? null : resolveOwnerOpAuthorityV7(build.action);
  const body = {
    manifestVersion: ROOTED_VAULT_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    vault: {
      contractVersion: build.contractVersion,
      vaultId: build.template.vaultId,
      covenantId: build.covenantId,
      descriptorHash: build.template.descriptorHash,
      tokenCovenantId: build.template.tokenCovenantId,
      templateVmHashBlake2b256: build.template.templateVmHash,
      templateGeometry: { prefixLen: build.template.templatePrefixLen, stateLen: build.template.templateStateLen, suffixLen: build.template.templateSuffixLen },
      orgRootCovenantId: build.template.orgRootCovenantId,
      rootTemplateVmHash: build.template.rootTemplateVmHash,
      rootGeometry: { prefixLen: build.template.rootPrefixLen, stateLen: build.template.rootStateLen, suffixLen: build.template.rootSuffixLen },
      recoveryPk: build.template.recoveryPk
    },
    asset: validated
      ? {
          descriptorHash: assets.computeDescriptorHash(validated),
          assetId: validated.assetId,
          displayName: validated.displayName,
          tokenStandard: validated.tokenStandard,
          decimalsDisplay: validated.decimalsDisplay,
          issuerPowers: { ...validated.issuerPowers },
          trust: Object.values(validated.issuerPowers).some(Boolean) ? "ISSUER_CONTROLLED" : "NO_DECLARED_ISSUER_POWERS"
        }
      : null,
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
    accounting: { token: { ...build.accounting.token }, kas: { ...build.accounting.kas } },
    policy:
      build.action === "tokenAgentSpend"
        ? {
            agentPolicy: build.callExtra
              ? {
                  agentPk: build.callExtra.agentPk,
                  tokenMaxPerSpend: build.callExtra.tokenMaxPerSpend,
                  tokenPeriodBudget: build.callExtra.tokenPeriodBudget,
                  periodLengthDaa: build.callExtra.periodLengthDaa,
                  periodStartDaa: build.callExtra.periodStartDaa,
                  tokenPeriodSpent: build.callExtra.tokenPeriodSpent,
                  agentMaxFeePerTx: build.callExtra.agentMaxFeePerTx,
                  agentMaxCarryKas: build.callExtra.agentMaxCarryKas,
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
              /* rc26 round-7 review R7-02: the owners approve the RULES being installed, never a bare root — the full new
               * delegate policy set travels in the manifest and the verifier binds stateAfter.agentRoot to its fold. */
              recoveryPk: null,
              agentSet: Array.isArray(build.agentSet) ? build.agentSet.map((policy) => ({ ...policy })) : null
            }
          : { recoveryPk: build.action === "ownerRecover" ? build.template.recoveryPk : null },
    transaction: { txId: build.txId, computeBudget: build.computeBudget, requiredFeeSompi: build.requiredFeeSompi },
    tokenSignatureScriptHex: build.tokenSignatureScriptHex
  };
  return deepFreeze({ ...body, manifestHash: computeManifestHashV1(body) });
}

/*
 * Verify ONE rooted-vault operation against the frozen transaction it rides
 * in. `frozen` is the parsed canonical transaction shared by every operation
 * in the manifest, so a vault op can never be verified against a different
 * transaction than the root it claims to ride.
 */
function verifyRootedVaultManifestV7({ manifest, frozen, descriptor = null, redeemHex = null, check }) {
  if (manifest.manifestVersion !== ROOTED_VAULT_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown rooted-vault manifest version — failing closed");
  const { manifestHash, ...body } = manifest;
  const tag = `vault[${manifest.vault.covenantId.slice(0, 8)}].`;
  check(`${tag}manifestHash`, computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
  const info = ownGet(ROOTED_VAULT_ACTIONS, manifest.action.sdkAction);
  check(`${tag}action`, !!info && info.role === manifest.action.role && info.terminal === manifest.action.terminal && info.mutationClass === manifest.action.mutationClass, "role/terminal/class derived from the action table");
  if (!info) return;

  /*
   * THE DECLARED TEMPLATE PINS MUST BE A WELL-FORMED v0.7 ROOTED VAULT
   * (gate I3c finding I3C-F2). The vault's template constants are what the
   * compiled covenant slices the root's state region by; the core knows the
   * v0.7 root layout exactly (467-byte region, non-empty prefix/suffix, a
   * non-sentinel root covenant id, the kcc20-state/1 token state length), so
   * a manifest declaring a geometry that no v0.7 root can have is refused
   * here instead of merely being displayed. Well-formed is not BOUND: Codex
   * checkpoint 7 (UX-02 / UX-13) binds every declared pin below — the frozen
   * v0.7-payment script rebuilt from the DECLARED pins around the reviewed
   * predecessor state must be byte for byte the vault's revealed redeem, whose
   * P2SH is the vault input's locking script (templatePinsBound); the root
   * pins must also agree with the root script the org-root verifier rebuilt
   * (rootEvidenceAgrees) and the token pins with the revealed token redeem
   * (tokenTemplateBound).
   */
  let templatePinFailure = null;
  try {
    normalizeTemplateV7({
      vaultId: manifest.vault.vaultId,
      descriptorHash: manifest.vault.descriptorHash,
      tokenCovenantId: manifest.vault.tokenCovenantId,
      templateVmHash: manifest.vault.templateVmHashBlake2b256,
      templatePrefixLen: manifest.vault.templateGeometry.prefixLen,
      templateStateLen: manifest.vault.templateGeometry.stateLen,
      templateSuffixLen: manifest.vault.templateGeometry.suffixLen,
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
  check(`${tag}templatePins`, templatePinFailure === null, templatePinFailure ?? "the declared template pins are a well-formed v0.7 rooted vault");

  const inputs = frozen.inputs;
  const outputs = frozen.outputs;
  const vaultIns = inputs.filter((i) => i.utxo.covenantId === manifest.vault.covenantId);
  check(`${tag}vaultInput`, vaultIns.length === 1 && vaultIns[0].utxo.amount === manifest.accounting.kas.predecessorFeeReserve, "exactly one vault input carrying the fee reserve");
  /* rc26 round-7 review R7-01: every input this operation spends — the vault, a token position, the fee input — is
   * spendable NOW. A non-zero `sequence` is a hidden RELATIVE LOCK (rusty-kaspa check_sequence_lock: without the DISABLE
   * bit the input is spendable only after `sequence & 0xffffffff` DAA of UTXO age); a lockTime on an owner operation is a
   * hidden waiting condition the review would never name. Only the organizational ROOT input may carry a sequence, and
   * only the covenant's own relative-age gate, bound by the OUTER manifest (rootInputSequence / rootInputSequenceZero).
   * The delegate spend's lockTime is bound exactly to its period rule below (lockTimeBound); every other action carries 0. */
  check(`${tag}inputSequencesZero`, inputs.every((i) => i.utxo.covenantId === manifest.vault.orgRootCovenantId || String(i.sequence) === "0"), "every non-root input carries sequence 0 — no hidden relative lock");
  if (manifest.action.sdkAction !== "tokenAgentSpend") check(`${tag}lockTimeZero`, String(frozen.lockTime) === "0", `an owner operation never carries a lock time (frozen lockTime ${frozen.lockTime})`);
  const before = normalizeStateV7(manifest.stateBefore.state);
  check(`${tag}predecessorReserve`, before.feeReserve.toString() === manifest.accounting.kas.predecessorFeeReserve, "stateBefore.feeReserve == accounting");

  /* Codex checkpoint 6 (UX-02 / UX-13): the committed COMPUTE BUDGETS are DERIVED from the reviewed operation and
   * the vault's pinned geometry through the one shared selector the SDK builds with (core/model/compute-budget-v7),
   * and both the frozen input and the manifest's declared budget must equal that derivation. A comparison between
   * two attacker-authored representations (frozen vs payload) is not a binding; this is. */
  {
    let expectedVaultBudget = null, budgetError = null;
    try {
      expectedVaultBudget = selectComputeBudgetV7({
        operation: manifest.action.sdkAction,
        templatePrefixLen: manifest.vault.templateGeometry.prefixLen,
        templateSuffixLen: manifest.vault.templateGeometry.suffixLen,
        rootPrefixLen: manifest.vault.rootGeometry.prefixLen,
        rootSuffixLen: manifest.vault.rootGeometry.suffixLen
      });
    } catch (e) { budgetError = e && e.message ? e.message : String(e); }
    check(
      `${tag}vaultComputeBudgetBound`,
      budgetError === null && vaultIns.length === 1 && Number.isInteger(vaultIns[0].computeBudget) && vaultIns[0].computeBudget === expectedVaultBudget && String(manifest.transaction.computeBudget) === String(expectedVaultBudget),
      budgetError ? `the vault input's compute budget could not be derived from the reviewed operation: ${budgetError}` : `the vault input commits exactly the derived compute budget ${expectedVaultBudget} for ${manifest.action.sdkAction} (frozen ${vaultIns.length === 1 ? vaultIns[0].computeBudget : "?"}, declared ${manifest.transaction.computeBudget})`
    );
  }

  /* AUTHORITY: an owner path must carry exactly one input of the pinned root
   * family, and must name the root path whose successor the covenant pins. */
  const rootIns = inputs.filter((i) => i.utxo.covenantId === manifest.vault.orgRootCovenantId);
  const rootOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.orgRootCovenantId);
  if (manifest.action.sdkAction === "tokenAgentSpend") {
    check(`${tag}agentPathHasNoRoot`, rootIns.length === 0 && rootOuts.length === 0 && manifest.action.requiresRootInput === false, "a delegate spend never touches the organizational root");
  } else {
    const authority = ownGet(ROOTED_VAULT_ACTIONS, manifest.action.sdkAction) ? resolveOwnerOpAuthorityV7(manifest.action.sdkAction) : null;
    check(`${tag}rootAuthorityPresent`, rootIns.length === 1 && rootOuts.length === 1 && manifest.action.requiresRootInput === true, "exactly one pinned root input and continuation output");
    check(
      `${tag}rootAuthorityPath`,
      !!authority && authority.rootActionName === manifest.action.requiredRootAction && authority.expectFrozenAfter.toString() === manifest.action.expectFrozenAfter && (authority.opSelector === null || authority.opSelector === manifest.action.opSelector),
      `${manifest.action.sdkAction} requires the root to run ${authority ? authority.rootActionName : "?"}`
    );
  }

  /* Codex checkpoint 7 (UX-02 / UX-13): THE DECLARED PINS AND THE REVIEWED PREDECESSOR STATE ARE BOUND TO THE VAULT THE
   * TRANSACTION ACTUALLY SPENDS — for EVERY operation, terminal ones included (the checkpoint-6 code bound the redeem
   * only on continuations and only to the input's P2SH + state; the pins the budgets and the recovery destination were
   * derived from stayed declared). The vault's predecessor redeem script is REQUIRED; its P2SH must be the vault input's
   * locking script (covered by every signature hash); its state region must decode to the reviewed predecessor state;
   * and — for the frozen v0.7-payment generation — the whole script rebuilt from the DECLARED template pins around that
   * state must be byte for byte this redeem (core/intent/vault-script-v7.js skeleton, proven against silverc). A declared
   * root/token geometry, template hash, descriptor hash, recovery key or predecessor state that is not the one compiled
   * into the spent vault therefore fails here, before any budget is derived from it and before any wallet is invoked. */
  const redeemPresent = typeof redeemHex === "string" && /^[0-9a-f]+$/i.test(redeemHex) && redeemHex.length % 2 === 0;
  check(`${tag}vaultRedeemPresent`, redeemPresent, "the vault's predecessor redeem script must be supplied for every operation (terminal included): it is the evidence the declared pins and predecessor state are bound to");
  let parts = null;
  let pinsBound = false;
  const isPaymentGeneration = manifest.vault.contractVersion === "policyvault-0.7-payment";
  if (redeemPresent) {
    let parseError = null;
    try { parts = vaultScriptV7.splitVaultRedeemHexV7(redeemHex); } catch (e) { parseError = e && e.message ? e.message : String(e); }
    check(`${tag}vaultRedeemWellFormed`, parseError === null, parseError ?? "the carried redeem script splits into prefix / 93-byte state region / suffix");
    if (parts) {
      const inSpk = vaultIns.length === 1 && vaultIns[0].utxo && vaultIns[0].utxo.scriptPublicKey ? vaultIns[0].utxo.scriptPublicKey : {};
      check(`${tag}vaultRedeemMatchesUtxo`, Number(inSpk.version || 0) === 0 && String(inSpk.scriptHex || "").toLowerCase() === vaultScriptV7.p2shSpkHexOf(redeemHex), "P2SH of the carried redeem == the vault input's locking script (covered by every signature hash)");
      const dec = parts.decoded;
      const beforeJson = { feeReserve: before.feeReserve.toString(), paused: before.paused.toString(), agentRoot: before.agentRoot, policyNonce: before.policyNonce.toString() };
      check(`${tag}vaultRedeemStateAgrees`, dec.vaultId === String(manifest.vault.vaultId).toLowerCase() && JSON.stringify(dec.state) === JSON.stringify(beforeJson), "the redeem's state region decodes to exactly the reviewed predecessor state under the reviewed vault id (terminal operations included)");
      const paymentScript = vaultScriptV7.isPaymentGenerationScriptV7(redeemHex);
      if (isPaymentGeneration) {
        let rebuilt = null, rebuildError = null;
        try { rebuilt = vaultScriptV7.reconstructVaultScriptHexV7({ template: vaultScriptV7.templatePinsFromManifestVault(manifest.vault), state: manifest.stateBefore.state }); } catch (e) { rebuildError = e && e.message ? e.message : String(e); }
        pinsBound = rebuildError === null && rebuilt === String(redeemHex).toLowerCase();
        check(
          `${tag}templatePinsBound`,
          pinsBound,
          rebuildError
            ? `the frozen v0.7-payment script could not be rebuilt from the declared template pins: ${rebuildError}`
            : pinsBound
              ? "the frozen v0.7-payment script rebuilt from the DECLARED template pins (token template hash + geometry, root covenant id + template hash + geometry, descriptor hash, recovery key) around the reviewed predecessor state is byte for byte the vault's revealed redeem — the pins are the ones compiled into the vault this transaction spends"
              : `the declared template pins / predecessor state do not rebuild the vault's revealed redeem script (${paymentScript ? "a substituted geometry, recovery key, template hash, descriptor hash or predecessor state" : "the revealed script is not a frozen v0.7-payment vault"})`
        );
      } else {
        check(`${tag}vaultGenerationAgrees`, !paymentScript, paymentScript ? `the vault input's script IS a frozen v0.7-payment vault but the manifest declares ${manifest.vault.contractVersion}` : `the declared generation ${manifest.vault.contractVersion} has no shared-core pin reconstruction yet — its template pins remain DECLARED (candidate profile; never mainnet)`);
      }
    }
  }

  if (info.terminal) {
    // rc20 review R5-04: a terminal operation continues NOTHING of its own family (the frozen ownerRecover branch requires nextStates.length == 0)
    const selfOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.covenantId);
    check(`${tag}terminalNoContinuation`, selfOuts.length === 0, "a terminal operation leaves no continuation of its own covenant");
  }
  if (!info.terminal) {
    const after = normalizeStateV7(manifest.stateAfter.state);
    const succ = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.covenantId);
    check(`${tag}successorOutput`, succ.length === 1 && succ[0].value === after.feeReserve.toString() && after.feeReserve.toString() === manifest.accounting.kas.successorFeeReserve, "exactly one successor carrying feeReserve");
    /* Codex checkpoint 6 (UX-02 / UX-13; closes the pre-sign gap recorded at rc20 review R5-04): the vault's SUCCESSOR
     * LOCKING SCRIPT is REBUILT from the vault's own revealed predecessor redeem script (prefix || state region ||
     * suffix — the frozen generation's template carriage) around the reviewed successor state, and the successor
     * output must carry exactly its P2SH. The redeem itself was bound above (P2SH == the vault input's locking script;
     * region == the reviewed predecessor state; Codex checkpoint 7: byte-equal to the script the declared pins rebuild). */
    const outSpk = succ.length === 1 && succ[0].scriptPublicKey ? succ[0].scriptPublicKey : {};
    if (parts) {
      let expectedSuccessorSpk = null, rebuildError = null;
      try { expectedSuccessorSpk = vaultScriptV7.reconstructVaultSuccessorSpkHexV7({ redeemHex, vaultId: manifest.vault.vaultId, state: manifest.stateAfter.state }); } catch (e) { rebuildError = e && e.message ? e.message : String(e); }
      check(`${tag}successorScriptReconstructed`, rebuildError === null && Number(outSpk.version || 0) === 0 && String(outSpk.scriptHex || "").toLowerCase() === expectedSuccessorSpk, rebuildError ? `the successor script could not be rebuilt from the reviewed successor state: ${rebuildError}` : "the successor output carries exactly the P2SH of the predecessor's template rebuilt around the reviewed successor state");
    }
    if (pinsBound) { // Codex checkpoint 7: the successor is ALSO the frozen generation's script rebuilt from the DECLARED pins around the reviewed successor state
      let fromPins = null, pinError = null;
      try { fromPins = vaultScriptV7.reconstructVaultScriptSpkHexV7({ template: vaultScriptV7.templatePinsFromManifestVault(manifest.vault), state: manifest.stateAfter.state }); } catch (e) { pinError = e && e.message ? e.message : String(e); }
      check(`${tag}successorScriptFromPins`, pinError === null && Number(outSpk.version || 0) === 0 && String(outSpk.scriptHex || "").toLowerCase() === fromPins, pinError ? `the successor script could not be rebuilt from the declared pins: ${pinError}` : "the successor output is exactly the frozen v0.7-payment script rebuilt from the declared pins around the reviewed successor state");
    }
    const consumed = before.feeReserve > after.feeReserve ? before.feeReserve - after.feeReserve : 0n;
    check(`${tag}reserveConsumed`, consumed.toString() === manifest.accounting.kas.reserveConsumed, `reserve consumed ${consumed}`);
    if (manifest.action.sdkAction !== "tokenAgentSpend") {
      const sel = manifest.action.opSelector;
      check(`${tag}selectorEffect`, selectorEffectHolds(sel, before, after), `selector ${sel} moves exactly the fields its covenant branch allows`);
    }
  }

  /* TOKEN domain */
  const family = manifest.vault.tokenCovenantId;
  const tokenIns = inputs.filter((i) => i.utxo.covenantId === family);
  const tokenOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === family);
  if (tokenIns.length > 0) { // Codex checkpoint 6 (UX-02 / UX-13): the token position's committed budget is the derived one too
    let expectedTokenBudget = null, tokenBudgetError = null;
    try { expectedTokenBudget = selectTokenInputBudgetV7({ templatePrefixLen: manifest.vault.templateGeometry.prefixLen, templateSuffixLen: manifest.vault.templateGeometry.suffixLen }); } catch (e) { tokenBudgetError = e && e.message ? e.message : String(e); }
    check(`${tag}tokenInputBudgetBound`, tokenBudgetError === null && tokenIns.every((i) => Number.isInteger(i.computeBudget) && i.computeBudget === expectedTokenBudget), tokenBudgetError ?? `every token input commits exactly the derived compute budget ${expectedTokenBudget}`);
  }
  const validated = descriptor ? assets.validateAssetDescriptor(descriptor) : null;
  if (validated) check(`${tag}descriptorPin`, assets.computeDescriptorHash(validated) === manifest.vault.descriptorHash, "descriptor hash == the vault's pin");

  /* rc21 review R6-02: when the transaction spends a token position, the token-side checks are REQUIRED — a missing
   * descriptor or a missing revealed redeem script fails closed instead of silently skipping the checks. */
  const tokenSigOk = typeof manifest.tokenSignatureScriptHex === "string" && /^[0-9a-f]+$/i.test(manifest.tokenSignatureScriptHex);
  if (tokenIns.length > 0) {
    check(`${tag}tokenDescriptorPresent`, !!validated, "a token position is spent: the vault's asset descriptor must be supplied and valid");
    check(`${tag}tokenSignaturePresent`, tokenSigOk, "a token position is spent: the revealed token redeem script must be present");
  }
  if (manifest.action.sdkAction === "tokenAgentSpend") {
    check(`${tag}familyShape`, tokenIns.length === 1 && tokenOuts.length === 2, "exactly 1 token input, 2 token outputs (self + recipient)");
    if (validated && tokenSigOk) {
      const redeemHex = assets.redeemFromSignatureScript(manifest.tokenSignatureScriptHex);
      const verified = assets.verifyTokenInputRedeem({ descriptor: validated, redeemHex });
      check(`${tag}tokenInputRedeemMatchesUtxo`, verified.p2shSpkHex === tokenIns[0].utxo.scriptPublicKey.scriptHex.toLowerCase(), "revealed redeem reproduces the token UTXO's P2SH");
      check(`${tag}tokenTemplateBound`, verified.geometry.prefixLen === manifest.vault.templateGeometry.prefixLen && verified.geometry.stateLen === manifest.vault.templateGeometry.stateLen && verified.geometry.suffixLen === manifest.vault.templateGeometry.suffixLen && verified.templateVmHashBlake2b256 === manifest.vault.templateVmHashBlake2b256, `the revealed token redeem's template (prefix ${verified.geometry.prefixLen} / state ${verified.geometry.stateLen} / suffix ${verified.geometry.suffixLen} bytes, in-VM hash ${String(verified.templateVmHashBlake2b256).slice(0, 8)}…) is exactly the template the vault pins — Codex checkpoint 7: the token budget is derived from bound geometry, never a declared one`);
      check(`${tag}tokenInputOwnedByVault`, verified.state.ownerIdentifier === manifest.vault.covenantId && verified.state.identifierType === OWNER_SCHEMES.COVENANT_ID && !verified.state.isMinter, "position owned via covenant-id/v1");
      const positionBefore = verified.state.amount;
      const spend = digits(manifest.accounting.token.spendAmount, "accounting.token.spendAmount");
      const positionAfter = digits(manifest.accounting.token.positionAfter, "accounting.token.positionAfter");
      check(`${tag}tokenConservation`, positionBefore.toString() === manifest.accounting.token.positionBefore && positionBefore === spend + positionAfter && spend > 0n, `${positionBefore} == ${spend} + ${positionAfter}`);
      const selfState = kcc20.encodeState({ ownerIdentifier: manifest.vault.covenantId, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: positionAfter, isMinter: false });
      const recipState = kcc20.encodeState({ ownerIdentifier: manifest.policy.recipient, identifierType: OWNER_SCHEMES.P2PK, amount: spend, isMinter: false });
      check(`${tag}selfContinuationReconstructed`, tokenOuts[0].scriptPublicKey.scriptHex.toLowerCase() === kcc20.p2shSpkHex(kcc20.reconstructRedeem(verified.prefixHex, selfState, verified.suffixHex)), "family output 0 == template(self state)");
      check(`${tag}recipientContinuationReconstructed`, tokenOuts[1].scriptPublicKey.scriptHex.toLowerCase() === kcc20.p2shSpkHex(kcc20.reconstructRedeem(verified.prefixHex, recipState, verified.suffixHex)), "family output 1 == template(recipient state)");
      const carryIn = BigInt(tokenIns[0].utxo.amount);
      const selfCarry = BigInt(tokenOuts[0].value);
      const recipCarry = BigInt(tokenOuts[1].value);
      check(`${tag}tokenFamilyKasNoLeak`, selfCarry + recipCarry >= carryIn, "self + recipient carry >= token input KAS");
      const policy = manifest.policy.agentPolicy ? normalizeTokenAgentPolicyV5(manifest.policy.agentPolicy) : null;
      check(`${tag}agentPolicyPresent`, !!policy, "agent policy carried");
      if (policy) {
        const proof = manifest.policy.agentProof;
        check(`${tag}agentProof`, verifyTokenAgentProofV5({ root: before.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) }), "leaf proven under the predecessor agentRoot");
        check(`${tag}spendWithinCap`, spend <= policy.tokenMaxPerSpend, `spend ${spend} <= cap ${policy.tokenMaxPerSpend}`);
        const periods = digits(manifest.policy.periodsElapsed, "policy.periodsElapsed");
        const newStart = periods >= 1n ? policy.periodStartDaa + periods * policy.periodLengthDaa : policy.periodStartDaa;
        const newSpent = periods >= 1n ? spend : policy.tokenPeriodSpent + spend;
        check(`${tag}spendWithinBudget`, newSpent <= policy.tokenPeriodBudget, `period spent ${newSpent} <= budget ${policy.tokenPeriodBudget}`);
        /*
         * THE ROLLOVER LOCKTIME, BOUND BOTH WAYS (gate I3c finding I3C-F1).
         * A period rollover is only honest if the transaction cannot enter the
         * DAG before the new period actually starts, and the builder pins
         * EQUALITY: lockTime = periodStartDaa + periodsElapsed x periodLengthDaa
         * on a rollover, and 0 otherwise. Two things are checked here, and both
         * must hold:
         *   1. the manifest's DECLARED lockTime is the frozen transaction's —
         *      otherwise the manifest could show one deadline while the bytes
         *      carry another;
         *   2. that value is EXACTLY the rule's value — a lockTime forged
         *      upward is refused by consensus (production-byte reject vector
         *      `neg_delegate_locktime_forged`), so the core refuses it too.
         * Before this check the v0.7 verifier bound neither, and a forged
         * lockTime passed local verification while consensus rejected it.
         */
        const expectedLockTime = periods >= 1n ? newStart : 0n;
        check(
          `${tag}lockTimeBound`,
          digits(manifest.policy.lockTime, "policy.lockTime") === BigInt(frozen.lockTime) && BigInt(frozen.lockTime) === expectedLockTime,
          `lockTime must be exactly ${expectedLockTime} for periodsElapsed ${periods} (declared ${manifest.policy.lockTime}, frozen ${frozen.lockTime})`
        );
        const after = normalizeStateV7(manifest.stateAfter.state);
        check(`${tag}successorRootDerived`, foldTokenAgentPolicyV5({ ...policy, periodStartDaa: newStart, tokenPeriodSpent: newSpent }, proof.siblingsHex, BigInt(proof.pathBits)) === after.agentRoot, "successor agentRoot == single-leaf fold of the advanced leaf");
        check(`${tag}carryWithinAgentCap`, recipCarry <= policy.agentMaxCarryKas, "recipient carry <= agentMaxCarryKas");
        check(`${tag}reserveWithinAgentCap`, BigInt(manifest.accounting.kas.reserveConsumed) <= policy.agentMaxFeePerTx, "reserve consumed <= agentMaxFeePerTx");
        const rp = manifest.policy.recipientProof;
        check(`${tag}recipientAllowlisted`, !!rp && rp.root === policy.agentRecipientRoot && verifyRecipientProof({ root: rp.root, recipient: manifest.policy.recipient, siblingsHex: rp.siblingsHex, pathBits: BigInt(rp.pathBits) }), "recipient proven under the agent's recipient root");
      }
    }
  } else if (manifest.action.sdkAction === "ownerRecover") {
    check(`${tag}payoutToPinnedRecoveryPk`, outputs[0].scriptPublicKey.scriptHex.toLowerCase() === `20${manifest.vault.recoveryPk}ac` && outputs[0].value === before.feeReserve.toString() && outputs[0].value === manifest.accounting.kas.terminalPayout, "output 0 pays the full reserve to the GENESIS-PINNED recoveryPk");
    check(`${tag}familyShape`, tokenIns.length <= 1 && tokenOuts.length === tokenIns.length, "0 or 1 token input with a matching continuation");
    // rc21 review R6-01: the token continuation carries EXACTLY the KAS the token input carried — the fee payer's change can never hide in it
    if (tokenIns.length === 1) check(`${tag}tokenCarryPreserved`, tokenOuts.length === 1 && tokenOuts[0].value === tokenIns[0].utxo.amount && tokenOuts[0].value === manifest.accounting.kas.tokenRecipientCarryKas && manifest.accounting.kas.tokenInputKas === tokenIns[0].utxo.amount, "the token continuation carries exactly the token input's KAS (accounting agrees)");
    if (tokenIns.length === 1 && validated && tokenSigOk) {
      const redeemHex = assets.redeemFromSignatureScript(manifest.tokenSignatureScriptHex);
      const verified = assets.verifyTokenInputRedeem({ descriptor: validated, redeemHex });
      check(`${tag}tokenInputRedeemMatchesUtxo`, verified.p2shSpkHex === tokenIns[0].utxo.scriptPublicKey.scriptHex.toLowerCase(), "revealed redeem reproduces the token UTXO's P2SH");
      check(`${tag}tokenTemplateBound`, verified.geometry.prefixLen === manifest.vault.templateGeometry.prefixLen && verified.geometry.stateLen === manifest.vault.templateGeometry.stateLen && verified.geometry.suffixLen === manifest.vault.templateGeometry.suffixLen && verified.templateVmHashBlake2b256 === manifest.vault.templateVmHashBlake2b256, `the revealed token redeem's template (prefix ${verified.geometry.prefixLen} / state ${verified.geometry.stateLen} / suffix ${verified.geometry.suffixLen} bytes, in-VM hash ${String(verified.templateVmHashBlake2b256).slice(0, 8)}…) is exactly the template the vault pins — Codex checkpoint 7: the token budget is derived from bound geometry, never a declared one`);
      const recoveryState = kcc20.encodeState({ ownerIdentifier: manifest.vault.recoveryPk, identifierType: OWNER_SCHEMES.P2PK, amount: verified.state.amount, isMinter: false });
      check(`${tag}tokensReturnToRecoveryPk`, tokenOuts[0].scriptPublicKey.scriptHex.toLowerCase() === kcc20.p2shSpkHex(kcc20.reconstructRedeem(verified.prefixHex, recoveryState, verified.suffixHex)) && verified.state.amount.toString() === manifest.accounting.token.recoveredToRecoveryPk, "the entire token amount moves to the pinned recoveryPk");
    }
  } else {
    check(`${tag}noTokenMovement`, tokenIns.length === 0 && tokenOuts.length === 0, "owner control ops never move tokens");
    if (manifest.action.sdkAction === "ownerSetAgentRoot") {
      /* rc26 round-7 review R7-02: `selectorEffect` deliberately leaves agentRoot free for this selector — so the root the
       * owners install MUST be derived from the policy set they are shown. The set travels in the manifest (agentSet);
       * its Merkle fold (core/model/agent-merkle-v5, the same fold the SDK builds with) must equal stateAfter.agentRoot.
       * A withheld, substituted, extended or emptied set, or a substituted root, refuses here. */
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
        try { foldRoot = buildTokenAgentTreeV5(set.map((p) => { const { recipients, ...policy } = p || {}; void recipients; return policy; })).root; } catch (e) { foldError = e.message; }
        const afterState = manifest.stateAfter && manifest.stateAfter.state ? normalizeStateV7(manifest.stateAfter.state) : null;
        check(`${tag}agentSetBound`, foldError === null && afterState !== null && foldRoot === afterState.agentRoot, foldError ? `the carried policy set is malformed: ${foldError}` : `stateAfter.agentRoot ${afterState ? afterState.agentRoot : "(none)"} must be the Merkle root of the carried policy set (${foldRoot})`);
      }
    }
  }
}

/* The per-selector state effect the covenant's mutually exclusive branches allow. */
function selectorEffectHolds(sel, before, after) {
  switch (sel) {
    case OWNER_OP_SELECTOR_V7.ownerSetAgentRoot:
      return after.feeReserve === before.feeReserve && after.paused === before.paused && after.policyNonce === before.policyNonce + 1n;
    case OWNER_OP_SELECTOR_V7.ownerTopUpReserve:
      return after.feeReserve > before.feeReserve && after.paused === before.paused && after.agentRoot === before.agentRoot && after.policyNonce === before.policyNonce;
    case OWNER_OP_SELECTOR_V7.ownerPause:
    case OWNER_OP_SELECTOR_V7.ownerEmergencyPause:
      return before.paused === 0n && after.paused === 1n && after.feeReserve === before.feeReserve && after.agentRoot === before.agentRoot && after.policyNonce === before.policyNonce;
    case OWNER_OP_SELECTOR_V7.ownerUnpause:
      return before.paused === 1n && after.paused === 0n && after.feeReserve === before.feeReserve && after.agentRoot === before.agentRoot && after.policyNonce === before.policyNonce;
    default:
      return false;
  }
}

/* ------------------------------------------------------------------ */
/* the ORGANIZATIONAL ROOT manifest                                     */
/* ------------------------------------------------------------------ */

/*
 * `build` is either a root-only build (kind "orgRootTransition") or a
 * rooted-vault build whose `rootAuthority` describes the root side. Either
 * way the root facts come from ONE place and the transaction is shared.
 */
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
  if (!ra) refuse("SCHEMA_INVALID", "a rooted-vault build without a root input cannot carry an organizational-root manifest");
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

function buildOrgRootIntentManifest({ build, vaultOperations = [], satisfiedApprovals = null }) {
  if (!build || typeof build !== "object") refuse("SCHEMA_INVALID", "a v0.7 build is required");
  const facts = rootFactsFrom(build);
  const before = setSummary(facts.prevState);
  const after = setSummary(facts.newState);
  const beforeKeys = new Set(before.slots.map((s) => s.publicKey));
  const afterKeys = new Set(after.slots.map((s) => s.publicKey));

  const ops = vaultOperations.map((op) => {
    const m = buildRootedVaultManifestV7({ build: op.build, descriptor: op.descriptor ?? null });
    return {
      covenantId: op.build.covenantId,
      vaultId: op.build.template.vaultId,
      tokenCovenantId: op.build.template.tokenCovenantId,
      sdkAction: op.build.action,
      opSelector: op.build.callExtra.opSelector ?? null,
      terminal: ownGet(ROOTED_VAULT_ACTIONS, op.build.action).terminal,
      manifest: m
    };
  });

  const body = {
    manifestVersion: ORG_ROOT_MANIFEST_VERSION_1,
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
    explanation: ORG_ROOT_EXPLANATION
  };
  return deepFreeze({ ...body, manifestHash: computeManifestHashV1(body) });
}

/*
 * Deterministic local verification: recompute every organizational fact from
 * the frozen transaction + the core codecs. Returns
 * { verdict: "VERIFIED" | "REFUSED", checks, failures }.
 */
function verifyOrgRootIntentManifest({ manifest, descriptors = {}, redeemScripts = {} }) {
  const checks = [];
  const failures = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail ?? null });
    if (!ok) failures.push({ name, detail: detail ?? null });
  };
  try {
    if (manifest.manifestVersion !== ORG_ROOT_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown org-root manifest version — failing closed");
    const { manifestHash, ...body } = manifest;
    check("manifestHash", computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
    check("explanationVerbatim", manifest.explanation === ORG_ROOT_EXPLANATION, "the fixed human explanation is carried verbatim");
    check("freshnessIsOutpointKillSwitch", manifest.freshness.kind === "ROOT_OUTPOINT_KILL_SWITCH" && manifest.freshness.expiry === null, "freshness is the root outpoint, never an expiry");

    const action = resolveRootActionV7(manifest.action.name);
    check("actionTable", action.action === manifest.action.code && action.entrypoint === manifest.action.entrypoint && action.class === manifest.action.authorityClass && action.quorumSource === manifest.action.quorumSource, "action / class / entrypoint / quorum source come from the action table");

    /* ---- root state derivation from the DECLARED states ---- */
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

    /* ---- threshold ---- */
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

    /* ---- the frozen transaction ---- */
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
    /* Codex checkpoint 6 (UX-02 / UX-13): the ROOT input's compute budget is DERIVED from the reviewed action and the
     * predecessor's active owner slots through the one shared selector the SDK builds with; the frozen input AND the
     * manifest's declared budget must both equal it. Every plain (non-covenant) input — the fee payer's — commits the
     * fixed ordinary budget. Nothing here trusts a value merely because two representations agree on it. */
    {
      let expectedRootBudget = null, rootBudgetError = null;
      try { expectedRootBudget = selectRootComputeBudgetV7({ actionName: manifest.action.name, activeOwnerSlots: before.activeCount }); } catch (e) { rootBudgetError = e && e.message ? e.message : String(e); }
      check(
        "rootComputeBudgetBound",
        rootBudgetError === null && rootIns.length === 1 && Number.isInteger(rootIns[0].computeBudget) && rootIns[0].computeBudget === expectedRootBudget && String(manifest.root.computeBudget) === String(expectedRootBudget),
        rootBudgetError ? `the root input's compute budget could not be derived: ${rootBudgetError}` : `the root input commits exactly the derived compute budget ${expectedRootBudget} for ${manifest.action.name} with ${before.activeCount} active slot(s) (frozen ${rootIns.length === 1 ? rootIns[0].computeBudget : "?"}, declared ${manifest.root.computeBudget})`
      );
      const plain = inputs.filter((i) => i.utxo.covenantId === null || i.utxo.covenantId === undefined);
      check("ordinaryInputBudgets", plain.every((i) => Number.isInteger(i.computeBudget) && i.computeBudget === V7_BUDGET.ORDINARY_INPUT), `every plain input commits the ordinary compute budget ${V7_BUDGET.ORDINARY_INPUT}`);
    }
    /* rc20 review R5-04 / rc19 review R4-07: the root's predecessor and successor LOCKING SCRIPTS are rebuilt from the
     * reviewed template + the before/after states through the exact frozen-generation reconstruction and must be the
     * scripts the transaction spends and creates (P2SH of the rebuilt script). */
    let rootEvidence = null; // Codex checkpoint 7: the rebuilt root script's REAL geometry + in-VM template identity, for the vault ops' root pins
    if (rootIns.length === 1 && rootOuts.length === 1) {
      let expectBefore = null, expectAfter = null, rebuildError = null;
      try {
        const tpl = { ...manifest.root.template, orgId: manifest.root.orgId };
        const rootBeforeHex = rootScriptV7.reconstructRootScriptHexV7({ template: tpl, state: manifest.rootState.before.state });
        expectBefore = rootScriptV7.p2shSpkHexOf(rootBeforeHex);
        expectAfter = rootScriptV7.p2shSpkHexOf(rootScriptV7.reconstructRootScriptHexV7({ template: tpl, state: manifest.rootState.after.state }));
        const prefixHex = rootBeforeHex.slice(0, rootScriptV7.ROOT_SCRIPT_PREFIX_HEX_V7.length);
        const suffixHex = rootBeforeHex.slice(rootScriptV7.ROOT_SCRIPT_PREFIX_HEX_V7.length + ROOT_STATE_LEN_V7 * 2);
        rootEvidence = { prefixLen: prefixHex.length / 2, stateLen: ROOT_STATE_LEN_V7, suffixLen: suffixHex.length / 2, templateVmHash: blake2bHex([hexToBytes(prefixHex), hexToBytes(suffixHex)], 32) };
      } catch (e) { rebuildError = e && e.message ? e.message : String(e); }
      const inSpk = rootIns[0].utxo.scriptPublicKey || {};
      const outSpk = rootOuts[0].scriptPublicKey || {};
      check("rootScriptsBound", rebuildError === null && Number(inSpk.version || 0) === 0 && String(inSpk.scriptHex || "").toLowerCase() === expectBefore && Number(outSpk.version || 0) === 0 && String(outSpk.scriptHex || "").toLowerCase() === expectAfter, rebuildError ? `the root script could not be rebuilt from the reviewed template and state: ${rebuildError}` : "the root input spends, and the root output creates, exactly the P2SH of the frozen v0.7 root script rebuilt from the reviewed template and states");
    }
    /* rc20 review R5-01: a root action never CREATES a covenant — every covenant-metadata output must continue the
     * covenant carried by the input it names, and an input continues at most once. (A genesis-shaped output whose
     * authorizing input is a plain P2PK input would be a valid NEW covenant under the upstream derivation rule and is
     * exactly how a hostile manifest would move the fee payer's change into an attacker script.) */
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
    /* rc21 review R6-04: the human-facing succession flag is DERIVED from the pinned successor key, never free-standing. */
    {
      const spk = String(manifest.root.template.successorPk || "").toLowerCase();
      const on = /^[0-9a-f]{64}$/.test(spk) && spk !== "00".repeat(32);
      check("successionFlag", manifest.root.template.successionEnabled === on, `template.successionEnabled must be ${on} for successorPk ${spk.slice(0, 8)}…`);
    }
    /* rc21 review R6-06: the FEE PAYER's change is bound here too (not only in the browser boundary): every output without
     * covenant metadata is either the ONE terminal payout (index 0, P2PK of the closing vault's pinned recovery key — its
     * value is bound by the rooted-vault verifier) or the fee payer's own P2PK change (at most one); a bare P2SH output
     * (no covenant metadata) is never legitimate. The fee payer is the owner of the LAST input's P2PK script. */
    {
      const fuelSpk = inputs.length ? String(inputs[inputs.length - 1].utxo.scriptPublicKey.scriptHex || "").toLowerCase() : "";
      const fuelOk = /^20[0-9a-f]{64}ac$/.test(fuelSpk) && inputs[inputs.length - 1].utxo.covenantId === null;
      const terminalOps = manifest.vaultOperations.filter((op) => op.manifest && op.manifest.action && op.manifest.action.terminal === true);
      const payoutSpks = new Set(terminalOps.map((op) => `20${String(op.manifest.vault.recoveryPk || "").toLowerCase()}ac`));
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
    /* rc26 round-7 review R7-01: no input other than the (age-gated) root may carry a sequence, and a root transaction
     * never carries a lockTime — a hostile server could otherwise attach a hidden waiting condition to an approved
     * owner action (an emergency pause that never lands) that the review would not name. */
    check("inputSequencesZero", inputs.every((i) => i.utxo.covenantId === manifest.root.covenantId || String(i.sequence) === "0"), "every non-root input carries sequence 0 — no hidden relative lock");
    check("lockTimeZero", String(frozen.lockTime) === "0", `a root transaction never carries a lock time (frozen lockTime ${frozen.lockTime})`);
    if (rootOuts.length === 1) {
      check("rootValueAfter", rootOuts[0].value === manifest.root.valueAfter, "the declared successor value is the output's");
      const loss = BigInt(manifest.root.valueBefore) - BigInt(rootOuts[0].value);
      check("rootValueRule", loss <= digits(manifest.root.template.rootMaxFeePerTx, "root.template.rootMaxFeePerTx") && loss.toString() === manifest.fee.rootValueLoss, `the root loses ${loss} <= rootMaxFeePerTx ${manifest.root.template.rootMaxFeePerTx}`);
    }

    /* ---- vault operations: every covenant family must be ACCOUNTED FOR ---- */
    const accounted = new Set([manifest.root.covenantId]);
    for (const op of manifest.vaultOperations) {
      /* rc20 review R5-01: the OUTER declaration is bound to the INNER (hash-checked, byte-verified) manifest — the
       * accounted families are the ones the inner manifest actually proves, never a free-standing outer string. */
      check(`vaultOp[${String(op.covenantId).slice(0, 8)}]idsBound`, op.manifest && op.manifest.vault && op.covenantId === op.manifest.vault.covenantId && (op.tokenCovenantId ?? null) === (op.manifest.vault.tokenCovenantId ?? null), "the declared vault covenant id and token covenant id are the inner manifest's");
      accounted.add(op.covenantId);
      accounted.add(op.tokenCovenantId);
      check(`vaultOp[${op.covenantId.slice(0, 8)}]declared`, inputs.some((i) => i.utxo.covenantId === op.covenantId), "the declared vault operation has an input in this transaction");
      check(`vaultOp[${op.covenantId.slice(0, 8)}]rootPin`, op.manifest.vault.orgRootCovenantId === manifest.root.covenantId, "the vault is pinned to THIS root");
      /* Codex checkpoint 7 (UX-02 / UX-13): the vault's declared ROOT pins — the geometry its covenant slices the root's
       * revealed redeem by and the root template identity it hashes — must be the REAL ones of the root script this
       * transaction spends (rebuilt above from the reviewed template + state and bound to the root input's P2SH), not a
       * free-standing declaration the budget selector would otherwise trust. */
      {
        const g = op.manifest.vault && op.manifest.vault.rootGeometry ? op.manifest.vault.rootGeometry : {};
        const agrees = !!rootEvidence && Number(g.prefixLen) === rootEvidence.prefixLen && Number(g.stateLen) === rootEvidence.stateLen && Number(g.suffixLen) === rootEvidence.suffixLen && String(op.manifest.vault.rootTemplateVmHash || "").toLowerCase() === rootEvidence.templateVmHash;
        check(`vaultOp[${op.covenantId.slice(0, 8)}]rootEvidenceAgrees`, agrees, rootEvidence ? `the vault's declared root geometry (${g.prefixLen} / ${g.stateLen} / ${g.suffixLen}) and root template hash must be the rebuilt root script's (${rootEvidence.prefixLen} / ${rootEvidence.stateLen} / ${rootEvidence.suffixLen}, ${rootEvidence.templateVmHash.slice(0, 8)}…)` : "the root script could not be rebuilt, so the vault's root pins cannot be bound");
      }
      /* The vault op's REQUIRED root path must be the path this manifest says
       * the root is taking. Without this, a manifest could show the owners a
       * full-quorum AUTHORIZE at the top while a vault operation underneath
       * declared it needs only the lighter FREEZE — the two halves of the
       * authority model must be checked against each other, not each against
       * itself. (Consensus refuses the mismatch either way; this is what makes
       * the mismatch VISIBLE before anyone signs.) */
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
      verifyRootedVaultManifestV7({ manifest: op.manifest, frozen, descriptor: descriptors[op.covenantId] ?? null, redeemHex: redeemScripts && typeof redeemScripts === "object" && !Array.isArray(redeemScripts) && Object.prototype.hasOwnProperty.call(redeemScripts, op.covenantId) ? redeemScripts[op.covenantId] : null, check });
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
  ORG_ROOT_MANIFEST_VERSION_1,
  ROOTED_VAULT_MANIFEST_VERSION_1,
  ORG_ROOT_EXPLANATION,
  ROOTED_VAULT_ACTIONS,
  VERIFIED_STATEMENT,
  buildOrgRootIntentManifest,
  verifyOrgRootIntentManifest,
  buildRootedVaultManifestV7,
  verifyRootedVaultManifestV7,
  canonicalJsonStringify,
  OWNER_SLOTS_V7,
  normalizeOwnerSetV7,
  normalizeTemplateV7,
  serializeRootStateHexV7
};
