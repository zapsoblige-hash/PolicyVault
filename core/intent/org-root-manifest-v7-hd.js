"use strict";

/*
 * policyvault-rooted-hd-vault-manifest/1 — the closed-schema, hash-committed
 * description of ONE frozen v0.7-payment-hd HIERARCHICAL DELEGATION
 * transaction (contracts/PolicyVault.v0.7-payment-hd.sil, contract
 * `PolicyVaultRootedTokenHD`), plus its deterministic LOCAL VERIFICATION
 * against the frozen transaction bytes. Wave 2 Track D, gate I2
 * (docs/postlaunch/hierarchical-delegation-design-freeze.md §4).
 *
 * SCOPE: this manifest family covers ONLY the five HD spend/delegation
 * entrypoints (`hdSpend` / `childSpendL2` / `childSpendL3` /
 * `delegateSetChildRoot1` / `delegateSetChildRoot2`) — every one of which
 * never touches the organizational root — so, unlike
 * core/intent/org-root-manifest-v7.js's `policyvault-rooted-vault-manifest/1`
 * family (which is verified ONLY inside a parent org-root manifest), THIS
 * family is STANDALONE VERIFIABLE: a signer can verify a delegate spend or
 * a parent's delegation without any root context at all, because its
 * authority never depends on one. The HD vault's OWNER operations
 * (ownerControl 0..4 / ownerRecover) are BYTE-IDENTICAL in substance to the
 * payment profile's and ride inside the ORG-ROOT manifest via the SAME
 * `policyvault-rooted-vault-manifest/1` family
 * (core/intent/org-root-manifest-v7.js's `buildRootedVaultManifestV7`,
 * widened additively to accept this contract version) — never restated
 * here.
 *
 * WHAT A SIGNER MUST BE ABLE TO SEE, and therefore what this manifest states
 * — and RE-DERIVES rather than trusts:
 *   - the FULL ANCESTOR CHAIN (every level's leaf, in ancestor order),
 *     re-verified to fold to the DECLARED prior agentRoot exactly as the
 *     covenant's `computeMerkleRoot` does;
 *   - the EFFECTIVE INTERSECTION (`core/model/hd-leaf-v7.js`'s
 *     `effectiveAuthority`) over that chain — the real cap/fee/carry/expiry
 *     bound a spend is limited to, never just the spending leaf's own
 *     advertised numbers;
 *   - each level's OWN period-budget counters, before and after;
 *   - for a delegation: exactly which level delegates and the new
 *     `childRoot`, with every OTHER field of the parent leaf pinned equal;
 *   - the HONEST EXPIRY STATEMENT
 *     (`core/model/hd-leaf-v7.js`'s `EXPIRY_IS_NOT_CONSENSUS_ENFORCED`) —
 *     `expiryDaa` is never presented as a consensus-enforced deadline;
 *   - that NO organizational-root input/output is present (the authority
 *     model in consensus terms: a spend/delegation authority is the
 *     ancestor chain, never the root).
 *
 * Status: IMPLEMENTED. Production-byte proof: sdk/tools/gen-v7-hd-vectors.js
 * + tests/vm/tests/v7_hd_sdk_integration.rs. NOT covenant-byte-frozen, NOT
 * production, NOT externally reviewed.
 */

const { computeManifestHashV1 } = require("./canonical");
const { ownGet } = require("../model/own-get"); // rc12 review R-02: own-property action lookups (prototype keys fail closed)
const assets = require("../assets");
const { normalizeTemplateV7, normalizeStateV7 } = require("../model/vault-state-v7");
const hd = require("../model/hd-leaf-v7");

const ROOTED_HD_VAULT_MANIFEST_VERSION_1 = "policyvault-rooted-hd-vault-manifest/1";
const CONTRACT_VERSION_V7_HD = "policyvault-0.7-payment-hd";
const VERIFIED_STATEMENT = "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.";

const HD_ACTIONS = Object.freeze({
  hdSpend: Object.freeze({ kind: "spend", level: 1 }),
  childSpendL2: Object.freeze({ kind: "spend", level: 2 }),
  childSpendL3: Object.freeze({ kind: "spend", level: 3 }),
  delegateSetChildRoot1: Object.freeze({ kind: "delegation", level: 1 }),
  delegateSetChildRoot2: Object.freeze({ kind: "delegation", level: 2 })
});

function refuse(code, message) {
  const e = new Error(message);
  e.code = code;
  throw e;
}
function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

const HD_EXPLANATION =
  "This transaction spends a hierarchical-delegation vault leaf at the ancestor chain shown below. Authority is the " +
  "INTERSECTION of every ancestor's limits — never just this leaf's own advertised numbers — and a delegation can " +
  "only ever narrow authority, never widen it. This never touches your organization's root: a delegate/child leaf " +
  "is never an owner. expiryDaa is a consistency check, not a Kaspa-enforced deadline; the real retirement " +
  "mechanisms are revocation (zeroing a childRoot) and the periodic budget.";

/* build.ancestorChain leaves are stored via hd.hdLeafToJson (a display
 * convenience), which adds a human-readable `expiryIsNotConsensusEnforced`
 * disclaimer field on top of the closed HD leaf layout. Strip it before
 * feeding a leaf back into a function that enforces the closed layout. */
function bareLeaf(leafJson) {
  const { expiryIsNotConsensusEnforced, ...leaf } = leafJson;
  void expiryIsNotConsensusEnforced;
  return leaf;
}

function effectiveAuthorityJson(chainForEffective) {
  const eff = hd.effectiveAuthority(chainForEffective.map((e) => ({ leaf: bareLeaf(e.leaf) })));
  return {
    level: eff.level,
    maxPerSpend: eff.maxPerSpend.toString(),
    maxFeePerTx: eff.maxFeePerTx.toString(),
    maxCarryKas: eff.maxCarryKas.toString(),
    expiryDaa: eff.expiryDaa.toString(),
    expiryIsNotConsensusEnforced: eff.expiryIsNotConsensusEnforced,
    perLevelBudgets: eff.perLevelBudgets.map((b) => ({ level: b.level, periodBudget: b.periodBudget.toString(), periodSpent: b.periodSpent.toString(), periodLengthDaa: b.periodLengthDaa.toString(), periodStartDaa: b.periodStartDaa.toString(), remaining: b.remaining.toString() }))
  };
}

/*
 * `build` is the frozen build object from
 * sdk/src/vault-builders-v7-hd.js's `buildHdSpendTransaction` /
 * `buildHdDelegationTransaction` (kind "hdTransition").
 */
function buildRootedHdVaultManifestV7({ build, descriptor = null }) {
  if (!build || build.contractVersion !== CONTRACT_VERSION_V7_HD || build.kind !== "hdTransition") {
    refuse("SCHEMA_INVALID", "a v0.7-payment-hd hdTransition build is required");
  }
  const info = ownGet(HD_ACTIONS, build.action);
  if (!info) refuse("UNKNOWN_ACTION", `unknown v0.7-payment-hd HD action ${JSON.stringify(build.action)} — failing closed`);
  let validated = null;
  if (descriptor) {
    validated = assets.validateAssetDescriptor(descriptor);
    if (assets.computeDescriptorHash(validated) !== build.template.descriptorHash) refuse("DESCRIPTOR_PIN_MISMATCH", "descriptor hash != the vault's pinned descriptorHash");
  }
  const t = build.template;
  const body = {
    manifestVersion: ROOTED_HD_VAULT_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    vault: {
      contractVersion: build.contractVersion,
      vaultId: t.vaultId,
      covenantId: build.covenantId,
      descriptorHash: t.descriptorHash,
      tokenCovenantId: t.tokenCovenantId,
      templateVmHashBlake2b256: t.templateVmHash,
      templateGeometry: { prefixLen: t.templatePrefixLen, stateLen: t.templateStateLen, suffixLen: t.templateSuffixLen },
      orgRootCovenantId: t.orgRootCovenantId,
      rootTemplateVmHash: t.rootTemplateVmHash,
      rootGeometry: { prefixLen: t.rootPrefixLen, stateLen: t.rootStateLen, suffixLen: t.rootSuffixLen },
      recoveryPk: t.recoveryPk
    },
    asset: validated
      ? { descriptorHash: assets.computeDescriptorHash(validated), assetId: validated.assetId, displayName: validated.displayName, tokenStandard: validated.tokenStandard, decimalsDisplay: validated.decimalsDisplay, issuerPowers: { ...validated.issuerPowers } }
      : null,
    action: { sdkAction: build.action, kind: info.kind, level: info.level, requiresRootInput: false },
    ancestorChain: build.ancestorChain,
    effectiveAuthority: info.kind === "spend" ? effectiveAuthorityJson(build.ancestorChain.map((e) => ({ leaf: e.leaf }))) : null,
    delegation: info.kind === "delegation" ? { delegatingParentLevel: build.delegatingParentLevel, newChildRoot: build.newChildRoot } : null,
    stateBefore: { stateId: build.predecessorStateId, state: build.stateJson, outpoint: build.predecessorOutpoint },
    stateAfter: { stateId: build.successorStateId, state: build.successorState },
    accounting: { token: { ...build.accounting.token }, kas: { ...build.accounting.kas } },
    transaction: { txId: build.txId, computeBudget: build.computeBudget, requiredFeeSompi: build.requiredFeeSompi, frozenCanonicalJson: build.frozenCanonicalJson },
    expiryStatement: hd.EXPIRY_IS_NOT_CONSENSUS_ENFORCED,
    explanation: HD_EXPLANATION
  };
  return deepFreeze({ ...body, manifestHash: computeManifestHashV1(body) });
}

/*
 * Deterministic LOCAL, STANDALONE verification: recompute every fact from
 * the manifest's OWN declared frozen transaction. Returns
 * { verdict: "VERIFIED" | "REFUSED", checks, failures, manifestHash }.
 */
function verifyRootedHdVaultManifestV7({ manifest }) {
  const checks = [];
  const failures = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail ?? null });
    if (!ok) failures.push({ name, detail: detail ?? null });
  };
  try {
    if (manifest.manifestVersion !== ROOTED_HD_VAULT_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown rooted-HD-vault manifest version — failing closed");
    const { manifestHash, ...body } = manifest;
    check("manifestHash", computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
    check("explanationVerbatim", manifest.explanation === HD_EXPLANATION, "the fixed human explanation is carried verbatim");
    check("expiryStatementVerbatim", manifest.expiryStatement === hd.EXPIRY_IS_NOT_CONSENSUS_ENFORCED, "the honest expiry disclaimer is carried verbatim");

    const info = ownGet(HD_ACTIONS, manifest.action.sdkAction);
    check("action", !!info && info.kind === manifest.action.kind && info.level === manifest.action.level, "action kind/level derived from the closed action table");
    check("neverTouchesRoot", manifest.action.requiresRootInput === false, "an HD spend/delegation authority is never the organizational root");
    if (!info) return deepFreeze({ verdict: "REFUSED", statement: null, checks, failures, manifestHash: manifest.manifestHash ?? null });

    /* ---- template pins are a well-formed v0.7 rooted vault ---- */
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
    check("templatePins", templatePinFailure === null, templatePinFailure ?? "the declared template pins are a well-formed v0.7 rooted vault");

    /* ---- the declared ancestor chain folds to the DECLARED prior agentRoot ---- */
    const before = normalizeStateV7(manifest.stateBefore.state);
    const after = normalizeStateV7(manifest.stateAfter.state);
    const chain = manifest.ancestorChain.map((entry, i) => {
      const leaf = hd.normalizeHdLeaf(bareLeaf(entry.leaf));
      if (entry.level !== i + 1) refuse("SCHEMA_INVALID", `ancestorChain[${i}].level ${entry.level} does not match its position ${i + 1}`);
      return { leaf, siblingsHex: entry.siblingsHex, pathBits: BigInt(entry.pathBits), level: entry.level };
    });
    let carried = null;
    for (let i = chain.length - 1; i >= 0; i--) {
      const e = chain[i];
      const maxDepth = e.level === 1 ? hd.MAX_AGENT_DEPTH : hd.MAX_CHILD_DEPTH;
      carried = hd.foldHdLeafHex(hd.hdLeafHash(e.leaf, e.level), e.siblingsHex, e.pathBits, maxDepth);
      if (carried === null) refuse("SCHEMA_INVALID", `ancestorChain[${i}] does not fully consume its pathBits`);
    }
    check("ancestorChainFoldsToStateBefore", carried === before.agentRoot, "the declared ancestor chain folds (Merkle) to the declared prior agentRoot, exactly like the covenant's computeMerkleRoot");
    const expiryCheck = hd.verifyExpiryMonotone(chain);
    check("expiryMonotoneDescending", expiryCheck.ok, expiryCheck.ok ? "every descendant's expiryDaa <= its parent's" : expiryCheck.message);

    /* ---- the declared successor agentRoot is the correct refold ---- */
    if (info.kind === "spend") {
      const spendAmount = BigInt(manifest.accounting.token.spendAmount);
      const periodsElapsedByLevel = manifest.ancestorChain.map((e) => BigInt(e.periodsElapsed));
      const newRoot = hd.nestedRefoldAfterSpend(chain, spendAmount, periodsElapsedByLevel);
      check("successorAgentRootIsCorrectSpendRefold", newRoot === after.agentRoot, "the declared successor agentRoot is the SAME nested refold the covenant computes for this spend");
      const eff = hd.effectiveAuthority(chain);
      check("effectiveAuthorityMatchesDeclared", eff.maxPerSpend.toString() === manifest.effectiveAuthority.maxPerSpend && eff.maxFeePerTx.toString() === manifest.effectiveAuthority.maxFeePerTx && eff.maxCarryKas.toString() === manifest.effectiveAuthority.maxCarryKas, "the declared effective authority is the true minimum-over-ancestors intersection");
      check("spendWithinEffectiveAuthority", spendAmount <= eff.maxPerSpend, `spendAmount ${spendAmount} <= effective maxPerSpend ${eff.maxPerSpend}`);
    } else {
      const newChildRoot = manifest.delegation.newChildRoot;
      const newRoot = hd.nestedRefoldAfterDelegation(chain, newChildRoot);
      check("successorAgentRootIsCorrectDelegationRefold", newRoot === after.agentRoot, "the declared successor agentRoot is the SAME nested refold the covenant computes for this delegation");
      const parentIdx = chain.length - 1;
      const delegCheck = hd.verifyDelegationOnlyChangesChildRoot(chain[parentIdx].leaf, { ...chain[parentIdx].leaf, childRoot: newChildRoot });
      check("delegationOnlyChangesChildRoot", delegCheck.ok, delegCheck.ok ? "every other field of the delegating parent is preserved" : `unexpectedly touched: ${delegCheck.violations.join(", ")}`);
      check("delegationActuallyChanges", newChildRoot !== chain[parentIdx].leaf.childRoot, "the covenant refuses a no-op delegation (newChildRoot == current childRoot)");
    }
    check("pausedAndNonceAlwaysPreserved", before.paused === after.paused && before.policyNonce === after.policyNonce, "neither a spend nor a delegation ever touches paused or policyNonce");
    check("reserveConsumedDeclared", (before.feeReserve - after.feeReserve).toString() === manifest.accounting.kas.reserveConsumed, "the declared reserveConsumed matches the state delta");
    if (info.kind === "delegation") check("delegationNeverMovesReserve", before.feeReserve === after.feeReserve, "a delegation op never moves the fee reserve");

    /* ---- the frozen transaction ---- */
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const inputs = frozen.inputs;
    const outputs = frozen.outputs;
    const totalIn = inputs.reduce((s, i) => s + BigInt(i.utxo.amount), 0n);
    const totalOut = outputs.reduce((s, o) => s + BigInt(o.value), 0n);
    check("feeExact", (totalIn - totalOut).toString() === manifest.transaction.requiredFeeSompi, "fee recomputed from the frozen bytes");
    const rootIns = inputs.filter((i) => i.utxo.covenantId === manifest.vault.orgRootCovenantId);
    const rootOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.orgRootCovenantId);
    check("noRootInputOrOutput", rootIns.length === 0 && rootOuts.length === 0, "an HD spend/delegation never carries the organizational root");
    const vaultIns = inputs.filter((i) => i.utxo.covenantId === manifest.vault.covenantId);
    check("vaultInputSingleton", vaultIns.length === 1 && vaultIns[0].utxo.amount === manifest.accounting.kas.predecessorFeeReserve, "exactly one vault input carrying the declared predecessor feeReserve");
    const succ = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.vault.covenantId);
    check("successorOutput", succ.length === 1 && succ[0].value === manifest.accounting.kas.successorFeeReserve, "exactly one successor output carrying the declared successor feeReserve");
    check("txIdDeclared", typeof manifest.transaction.txId === "string" && /^[0-9a-f]{64}$/.test(manifest.transaction.txId), "the transaction id is well-formed");
  } catch (e) {
    failures.push({ name: "exception", detail: `${e.code ?? "ERROR"}: ${e.message}` });
    checks.push({ name: "exception", ok: false, detail: `${e.code ?? "ERROR"}: ${e.message}` });
  }
  const verdict = failures.length === 0 ? "VERIFIED" : "REFUSED";
  return deepFreeze({ verdict, statement: verdict === "VERIFIED" ? VERIFIED_STATEMENT : null, checks, failures, manifestHash: manifest.manifestHash ?? null });
}

module.exports = {
  ROOTED_HD_VAULT_MANIFEST_VERSION_1,
  CONTRACT_VERSION_V7_HD,
  HD_ACTIONS,
  VERIFIED_STATEMENT,
  HD_EXPLANATION,
  buildRootedHdVaultManifestV7,
  verifyRootedHdVaultManifestV7
};
