"use strict";
const { ownGet } = require("../model/own-get");

/*
 * policyvault-controller-intent-manifest/1 — the closed-schema,
 * hash-committed description of ONE frozen v0.6 NON-SWAP controller
 * transaction (tokenAgentSpend, the six owner control operations,
 * ownerRecover, and a v0.6-labelled tokenDeposit), plus its deterministic
 * LOCAL PRE-SIGN VERIFICATION against the frozen transaction bytes.
 *
 * WHY THIS EXISTS (the application-integration gap this closes):
 * `docs/postlaunch/v0.6-byte-freeze-readiness.md` limitation 8 recorded that
 * "v0.6-labelled manifests exist for swaps only; spend/owner/recover on a
 * v0.6 controller are verified by the builder's frozen bytes (the v0.5 token
 * manifest is version-pinned to v0.5)". `core/intent/token-manifest-v5.js`
 * REFUSES any build whose contractVersion is not `policyvault-0.5`, and
 * `core/intent/swap-manifest-v6.js` REFUSES any build without `build.swap`,
 * so every non-swap v0.6 operation had NO manifest and therefore NO
 * signer-side independent recomputation. That is exactly the condition the
 * architecture target forbids: a financial fact whose only local proof is
 * "the builder said so". This module gives the v0.6 controller the SAME
 * local pre-sign verification v0.5 already has, additively — v0.5 and the
 * v0.6 swap manifest are untouched.
 *
 * WHAT THE SIGNER GETS, as SEPARATE sections: controller identity; token
 * asset identity + issuer trust; the THREE v0.6 KAS domains stated apart
 * (fee reserve / swap principal / token-note carries); the token domain;
 * the agent authority actually exercised (leaf + Merkle proof + caps +
 * budget + successor-root fold); the owner authority actually exercised
 * (op selector + external funding); and the verification result. NOTHING
 * here is trusted as stated: verify() recomputes every financial fact from
 * the frozen transaction + the accepted descriptor + the core's own codecs
 * and refuses on any mismatch.
 *
 * FAIL-CLOSED VERSION ROUTING: this module handles `policyvault-0.6`
 * NON-SWAP builds only. A swap build (tokenAtomicSell / tokenAtomicBuy)
 * is REFUSED here and belongs to swap-manifest-v6.js; a v0.5 build is
 * REFUSED here and belongs to token-manifest-v5.js. `core/intent/router.js`
 * performs that dispatch and refuses every unknown combination.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/intent/test/token-manifest-v6.test.js,
 * sdk/test/token-manifest-v6.test.js over REAL builds). The codecs it
 * recomputes with are the SAME modules tests/vm/tests/v6_sdk_integration.rs
 * executes byte-for-byte on the real engine.
 */

const { canonicalJsonStringify, computeManifestHashV1 } = require("./canonical");
const assets = require("../assets");
const { kcc20 } = assets;
const { normalizeTokenAgentPolicyV6, verifyTokenAgentProofV6, foldTokenAgentPolicyV6 } = require("../model/agent-merkle-v6");
const { verifyRecipientProof } = require("../model/recipient-merkle-v3");
const { normalizeStateV6, normalizeStateV6ForRecovery, OWNER_OP_SELECTOR_V6 } = require("../model/vault-state-v6");
const { calcStorageMass, cellsOfFrozenTx, STORAGE_MASS_LIMIT } = require("../model/storage-mass");
const { OWNER_SCHEMES } = require("../model/token-amounts");

const CONTROLLER_MANIFEST_VERSION_1 = "policyvault-controller-intent-manifest/1";
const CONTRACT_VERSION_V6 = "policyvault-0.6";

/*
 * The closed action table. `role` and `terminal` are DERIVED here and
 * re-derived by verify(); a manifest that states a different role/terminal
 * than the table says is refused, so a hostile builder cannot relabel an
 * owner operation as an agent one (or a terminal one as continuing).
 * `opSelector` is the covenant's own ownerControl selector — pinned so a
 * relabelled owner op refuses.
 */
const ACTIONS = Object.freeze({
  tokenAgentSpend: Object.freeze({ role: "agent", terminal: false, opSelector: null }),
  ownerSetAgentRoot: Object.freeze({ role: "owner", terminal: false, opSelector: OWNER_OP_SELECTOR_V6.ownerSetAgentRoot }),
  ownerTopUpReserve: Object.freeze({ role: "owner", terminal: false, opSelector: OWNER_OP_SELECTOR_V6.ownerTopUpReserve }),
  ownerPause: Object.freeze({ role: "owner", terminal: false, opSelector: OWNER_OP_SELECTOR_V6.ownerPause }),
  ownerUnpause: Object.freeze({ role: "owner", terminal: false, opSelector: OWNER_OP_SELECTOR_V6.ownerUnpause }),
  ownerSetSwapRoot: Object.freeze({ role: "owner", terminal: false, opSelector: OWNER_OP_SELECTOR_V6.ownerSetSwapRoot }),
  ownerFundSwapPrincipal: Object.freeze({ role: "owner", terminal: false, opSelector: OWNER_OP_SELECTOR_V6.ownerFundSwapPrincipal }),
  ownerRecover: Object.freeze({ role: "owner", terminal: true, opSelector: null }),
  /* user-owned position -> controller (no controller input; the family leader authorizes with the user's signature) */
  tokenDeposit: Object.freeze({ role: "tokenOwner", terminal: false, opSelector: null })
});

/* Handled by core/intent/swap-manifest-v6.js — named here so the refusal is specific, never a silent default. */
const SWAP_ACTIONS = Object.freeze(["tokenAtomicSell", "tokenAtomicBuy"]);

const VERIFIED_STATEMENT = "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.";

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
function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}
function p2pkSpk(pk) {
  return `20${pk}ac`;
}

/* The asset section, identical in shape to the v0.5 and v0.6-swap manifests. */
function assetSection({ validated, descriptorHash, templateIndex }) {
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  return {
    descriptorHash,
    assetId: validated.assetId,
    displayName: validated.displayName,
    tokenStandard: validated.tokenStandard,
    decimalsDisplay: validated.decimalsDisplay,
    templateIndex,
    templateVmHashBlake2b256: tpl ? tpl.templateVmHashBlake2b256 : null,
    templateKcc1HashBlake3: tpl && tpl.templateKcc1HashBlake3 !== undefined ? tpl.templateKcc1HashBlake3 : null,
    issuerPowers: { ...validated.issuerPowers },
    trust: Object.values(validated.issuerPowers).some(Boolean) ? "ISSUER_CONTROLLED" : "NO_DECLARED_ISSUER_POWERS"
  };
}

function controllerSection(template, covenantId) {
  return {
    contractVersion: CONTRACT_VERSION_V6,
    vaultId: template.vaultId,
    owner: template.owner,
    covenantId,
    descriptorHash: template.descriptorHash,
    tokenCovenantId: template.tokenCovenantId,
    templateVmHashBlake2b256: template.templateVmHash,
    templateGeometry: { prefixLen: template.templatePrefixLen, stateLen: template.templateStateLen, suffixLen: template.templateSuffixLen }
  };
}

/* KIP-9 storage mass over the frozen shape (a CONSENSUS dimension: an
 * over-limit value makes the transaction invalid regardless of fee). */
function storageMassOf(frozen) {
  const { inputCells, outputCells } = cellsOfFrozenTx(frozen);
  return calcStorageMass(inputCells, outputCells);
}

/*
 * Build the manifest from a v0.6 SDK build (vault-builders-v6 output) +
 * the accepted descriptor + the agent registry facts the build used.
 */
function buildControllerIntentManifestV6({ build, descriptor, agentPolicy = null, recipients = null }) {
  if (!build || typeof build !== "object") refuse("SCHEMA_INVALID", "a v0.6 build is required");
  if (build.contractVersion !== CONTRACT_VERSION_V6) refuse("SCHEMA_INVALID", `a ${CONTRACT_VERSION_V6} build is required (got ${JSON.stringify(build.contractVersion ?? null)}) — failing closed`);
  if (build.kind === "tokenDeposit") return buildDepositManifestV6({ build, descriptor });
  if (build.kind !== "transition") refuse("SCHEMA_INVALID", `a v0.6 transition or tokenDeposit build is required (got kind ${JSON.stringify(build.kind ?? null)})`);
  if (SWAP_ACTIONS.includes(build.action) || build.swap) {
    refuse("WRONG_MANIFEST_FOR_ACTION", `${JSON.stringify(build.action)} is an ATOMIC SWAP — use core/intent/swap-manifest-v6.js (policyvault-swap-intent-manifest/1); this manifest never describes a swap`);
  }
  const info = ownGet(ACTIONS, build.action);
  if (!info) refuse("UNKNOWN_ACTION", `unknown v0.6 action ${JSON.stringify(build.action)} — failing closed`);

  const validated = assets.validateAssetDescriptor(descriptor);
  const descriptorHash = assets.computeDescriptorHash(validated);
  if (descriptorHash !== build.template.descriptorHash) refuse("DESCRIPTOR_PIN_MISMATCH", "descriptor hash != the controller's pinned descriptorHash");
  const templateIndex = build.asset?.templateIndex ?? 0;

  const frozen = JSON.parse(build.frozenCanonicalJson);
  const body = {
    manifestVersion: CONTROLLER_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    controller: controllerSection(build.template, build.covenantId),
    asset: assetSection({ validated, descriptorHash, templateIndex }),
    action: { sdkAction: build.action, role: info.role, terminal: info.terminal, opSelector: info.opSelector },
    transaction: {
      txId: build.txId,
      frozenCanonicalJson: build.frozenCanonicalJson,
      computeBudget: build.computeBudget,
      requiredFeeSompi: build.requiredFeeSompi,
      storageMass: storageMassOf(frozen).toString()
    },
    stateBefore: { stateId: build.predecessorStateId, state: build.stateJson, outpoint: build.predecessorOutpoint },
    stateAfter: info.terminal ? null : { stateId: build.successorStateId, state: build.successorState },
    accounting: { token: { ...build.accounting.token }, kas: { ...build.accounting.kas } },
    policy:
      build.action === "tokenAgentSpend"
        ? {
            agentPolicy: agentPolicy ? { ...agentPolicy } : null,
            agentProof: build.agentProof ? { ...build.agentProof } : null,
            recipient: build.payment.recipient,
            recipientProof: build.recipientProof ? { ...build.recipientProof } : null,
            recipients: recipients ? [...recipients] : null,
            periodsElapsed: build.callExtra.periodsElapsed,
            lockTime: build.frozen.lockTime.toString()
          }
        : { opSelector: build.callExtra.opSelector ?? null, externalFunding: build.accounting.kas.externalFunding },
    tokenSignatureScriptHex: build.tokenSignatureScriptHex
  };
  const manifest = { ...body, manifestHash: computeManifestHashV1(body) };
  return deepFreeze(manifest);
}

/*
 * A v0.6-LABELLED deposit (buildTokenDepositV6): mechanically the v0.5
 * deposit (`build.depositMechanics === "policyvault-0.5"`; no controller
 * input — the family leader authorizes with the user's own signature),
 * carried under the v0.6 lineage so a deposit into a v0.6 controller is
 * never described by a manifest pinned to the v0.5 lineage. Before this
 * module existed, `buildTokenDepositV6` produced a build that NO manifest
 * accepted (the v0.5 manifest refuses its contractVersion), which is why
 * the live v0.6 proof had to fall back to the v0.5 builder.
 */
function buildDepositManifestV6({ build, descriptor }) {
  if (build.depositMechanics !== "policyvault-0.5") refuse("SCHEMA_INVALID", "a v0.6 tokenDeposit build must declare depositMechanics policyvault-0.5 — failing closed");
  const validated = assets.validateAssetDescriptor(descriptor);
  const descriptorHash = assets.computeDescriptorHash(validated);
  if (descriptorHash !== build.controller.template.descriptorHash) refuse("DESCRIPTOR_PIN_MISMATCH", "descriptor hash != the controller's pinned descriptorHash");
  const frozen = JSON.parse(build.frozenCanonicalJson);
  const body = {
    manifestVersion: CONTROLLER_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    controller: controllerSection(build.controller.template, build.controller.covenantId),
    asset: assetSection({ validated, descriptorHash, templateIndex: build.asset.templateIndex }),
    action: { sdkAction: "tokenDeposit", role: "tokenOwner", terminal: false, opSelector: null },
    transaction: {
      txId: build.txId,
      frozenCanonicalJson: build.frozenCanonicalJson,
      computeBudget: build.frozen.inputs[0].computeBudget,
      requiredFeeSompi: build.requiredFeeSompi,
      storageMass: storageMassOf(frozen).toString()
    },
    stateBefore: null,
    stateAfter: null,
    accounting: { token: { ...build.accounting.token }, kas: { ...build.accounting.kas } },
    policy: { userPk: build.userPk, tokenNewStates: [...build.tokenNewStates], depositMechanics: build.depositMechanics },
    tokenSignatureScriptHex: null
  };
  const manifest = { ...body, manifestHash: computeManifestHashV1(body) };
  return deepFreeze(manifest);
}

/*
 * Deterministic local PRE-SIGN verification: recompute every financial
 * fact from the frozen transaction + descriptor + core codecs. Returns
 * { verdict: "VERIFIED" | "REFUSED", checks, failures, manifestHash }.
 */
function verifyControllerIntentManifestV6({ manifest, descriptor }) {
  const checks = [];
  const failures = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail ?? null });
    if (!ok) failures.push({ name, detail: detail ?? null });
  };
  try {
    if (!manifest || typeof manifest !== "object") refuse("SCHEMA_INVALID", "manifest must be an object");
    if (manifest.manifestVersion !== CONTROLLER_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown controller manifest version — failing closed");
    const { manifestHash, ...body } = manifest;
    check("manifestHash", computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
    const info = ownGet(ACTIONS, manifest.action?.sdkAction);
    if (!info) refuse("UNKNOWN_ACTION", "unknown action");
    check(
      "actionRole",
      info.role === manifest.action.role && info.terminal === manifest.action.terminal && info.opSelector === (manifest.action.opSelector ?? null),
      "role/terminal/opSelector derived from the action table"
    );
    check("contractVersion", manifest.controller.contractVersion === CONTRACT_VERSION_V6, "v0.6 lineage only");

    /* asset + descriptor pins */
    const validated = assets.validateAssetDescriptor(descriptor);
    const dh = assets.computeDescriptorHash(validated);
    check("descriptorHashPin", dh === manifest.asset.descriptorHash && dh === manifest.controller.descriptorHash, "descriptor hash == asset.descriptorHash == controller pin");
    check("descriptorFamily", validated.tokenCovenantId === manifest.controller.tokenCovenantId, "descriptor family == controller pin");
    const tpl = validated.acceptedTransferTemplates[manifest.asset.templateIndex];
    check(
      "templatePin",
      !!tpl &&
        tpl.templateVmHashBlake2b256 === manifest.controller.templateVmHashBlake2b256 &&
        tpl.prefixLen === manifest.controller.templateGeometry.prefixLen &&
        tpl.suffixLen === manifest.controller.templateGeometry.suffixLen,
      "descriptor template == controller pin (hash + geometry)"
    );
    check("issuerPowersVerbatim", JSON.stringify(manifest.asset.issuerPowers) === JSON.stringify(validated.issuerPowers), "issuer powers surfaced verbatim");

    /* frozen transaction: the only source of financial truth below */
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const inputs = frozen.inputs;
    const outputs = frozen.outputs;
    const totalIn = inputs.reduce((s, i) => s + BigInt(i.utxo.amount), 0n);
    const totalOut = outputs.reduce((s, o) => s + BigInt(o.value), 0n);
    const fee = totalIn - totalOut;
    check("feeExact", fee > 0n && fee.toString() === manifest.accounting.kas.fee && fee.toString() === manifest.transaction.requiredFeeSompi, `fee ${fee}`);
    const storage = storageMassOf(frozen);
    check("storageMass", storage <= STORAGE_MASS_LIMIT && storage.toString() === manifest.transaction.storageMass, `KIP-9 storage mass ${storage} <= ${STORAGE_MASS_LIMIT}`);

    if (manifest.action.sdkAction === "tokenDeposit") {
      verifyDepositV6(manifest, validated, check, frozen, fee);
      const verdictD = failures.length === 0 ? "VERIFIED" : "REFUSED";
      return deepFreeze({ verdict: verdictD, statement: verdictD === "VERIFIED" ? VERIFIED_STATEMENT : null, checks, failures, manifestHash: manifest.manifestHash ?? null });
    }

    /* ---------------- KAS domains: reserve + principal, stated apart ---------------- */
    /*
     * BREAK-GLASS PARSE, quarantined exactly as the builder quarantines it
     * (`vault-builders-v6.js`: `allowMalformedState` is accepted ONLY for
     * ownerRecover). A controller whose stored state is malformed —
     * out-of-range `paused`/`policyNonce` — can still be recovered by its
     * owner, and refusing to describe that transaction would push the owner
     * to sign it with NO local verification at all, which is the exact
     * failure mode this manifest exists to remove. So ownerRecover falls
     * back to the shape-only recovery parse; every continuing action keeps
     * the strict parse (a malformed state there throws -> REFUSED). The
     * fallback is never silent: `stateParse` is always reported, and the
     * payout is still proven against the frozen output bytes below.
     */
    let before;
    let strictParse = true;
    try {
      before = normalizeStateV6(manifest.stateBefore.state);
    } catch (e) {
      if (!info.terminal) throw e;
      before = normalizeStateV6ForRecovery(manifest.stateBefore.state);
      strictParse = false;
    }
    check(
      "stateParse",
      strictParse || (info.terminal && before.recoveryParse === true),
      strictParse ? "predecessor state parsed under the strict v0.6 layout" : "BREAK-GLASS: the predecessor state is MALFORMED under the strict v0.6 layout and was parsed shape-only; only ownerRecover may consume it, and the payout is proven from the transaction bytes"
    );
    const controllerValueBefore = before.feeReserve + before.swapPrincipal;
    const ctrlIn = inputs[0];
    check(
      "controllerInput",
      ctrlIn.utxo.covenantId === manifest.controller.covenantId && BigInt(ctrlIn.utxo.amount) === controllerValueBefore,
      "input 0 is the controller carrying feeReserve + swapPrincipal"
    );
    check(
      "predecessorDomains",
      before.feeReserve.toString() === manifest.accounting.kas.predecessorFeeReserve && before.swapPrincipal.toString() === manifest.accounting.kas.predecessorSwapPrincipal,
      "stateBefore reserve/principal == accounting"
    );

    const family = manifest.controller.tokenCovenantId;
    check(
      "noForeignCovenantInputs",
      inputs.every((i, idx) => idx === 0 || i.utxo.covenantId === null || i.utxo.covenantId === family),
      "every non-controller input is plain fuel or the pinned token family — no third covenant"
    );

    let after = null;
    if (!info.terminal) {
      after = normalizeStateV6(manifest.stateAfter.state);
      const controllerValueAfter = after.feeReserve + after.swapPrincipal;
      const succ = outputs.filter((o) => o.covenant && o.covenant.covenantId === manifest.controller.covenantId);
      check(
        "successorOutput",
        succ.length === 1 && BigInt(succ[0].value) === controllerValueAfter,
        "exactly one successor output carrying feeReserve' + swapPrincipal'"
      );
      check(
        "successorDomains",
        after.feeReserve.toString() === manifest.accounting.kas.successorFeeReserve && after.swapPrincipal.toString() === manifest.accounting.kas.successorSwapPrincipal,
        "stateAfter reserve/principal == accounting"
      );
      /*
       * The fee reserve moves in exactly two ways, and never both at once:
       *   - an AGENT operation may CONSUME from it (0 <= consumed <= the
       *     exact network fee — the covenant's own bound);
       *   - an OWNER ownerTopUpReserve ADDS externally funded value to it
       *     (declared reserveConsumed is then 0, and the per-action
       *     equations below prove the increase equals the funding).
       * Treating the reserve as monotonically decreasing would wrongly
       * refuse a legitimate top-up, so the direction is checked per role.
       */
      const reserveDelta = after.feeReserve - before.feeReserve;
      const declaredConsumed = digits(manifest.accounting.kas.reserveConsumed, "accounting.kas.reserveConsumed");
      if (info.role === "agent") {
        check(
          "reserveConsumed",
          reserveDelta === -declaredConsumed && declaredConsumed >= 0n && declaredConsumed <= fee,
          `agent op: reserve consumed ${declaredConsumed} (delta ${reserveDelta}) <= fee ${fee}`
        );
      } else {
        check(
          "reserveConsumed",
          declaredConsumed === 0n && reserveDelta >= 0n,
          `owner op: consumes no reserve (declared ${declaredConsumed}, delta ${reserveDelta}) — the fee comes from the owner's fuel input`
        );
      }
      const principalDelta = after.swapPrincipal - before.swapPrincipal;
      check("principalDelta", principalDelta.toString() === manifest.accounting.kas.principalDelta, `principal delta ${principalDelta}`);
    }

    /* ---------------- per-action state equations + authority ---------------- */
    if (manifest.action.sdkAction === "tokenAgentSpend") {
      verifySpendV6({ manifest, validated, check, frozen, inputs, outputs, before, after, fee, family });
    } else if (manifest.action.sdkAction === "ownerRecover") {
      verifyRecoverV6({ manifest, validated, check, inputs, outputs, before, family });
    } else {
      verifyOwnerControlV6({ manifest, check, before, after, family, inputs, outputs });
    }
  } catch (e) {
    const detail = `${e.code ?? "ERROR"}: ${e.message}`;
    failures.push({ name: "exception", detail });
    checks.push({ name: "exception", ok: false, detail });
  }
  const verdict = failures.length === 0 ? "VERIFIED" : "REFUSED";
  return deepFreeze({ verdict, statement: verdict === "VERIFIED" ? VERIFIED_STATEMENT : null, checks, failures, manifestHash: manifest?.manifestHash ?? null });
}

/*
 * tokenAgentSpend: the token domain reconstructed from the revealed redeem
 * + the descriptor template (never from labels), the agent's authority
 * proven under the LIVE agentRoot, the caps/budget arithmetic redone, and
 * the successor agentRoot re-folded from the advanced leaf up the SAME
 * co-path. The two v0.6-only domains (swapRoot, swapPrincipal) must be
 * untouched: a spend can never move protected principal or re-approve a
 * venue.
 */
function verifySpendV6({ manifest, validated, check, frozen, inputs, outputs, before, after, fee, family }) {
  check(
    "spendStatePreserved",
    before.paused === 0n && after.paused === 0n && before.policyNonce === after.policyNonce && before.swapRoot === after.swapRoot && before.swapPrincipal === after.swapPrincipal,
    "spend preserves nonce/paused(0)/swapRoot/swapPrincipal — no owner authority, no principal movement"
  );
  check("spendAdvancesAgentRoot", before.agentRoot !== after.agentRoot, "agentRoot advanced (period accounting recorded on chain)");

  const tokenIns = inputs.filter((i) => i.utxo.covenantId === family);
  const tokenOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === family);
  check("familyShape", tokenIns.length === 1 && tokenOuts.length === 2, "exactly 1 token input, 2 token outputs (self + recipient)");
  if (tokenIns.length !== 1 || tokenOuts.length !== 2) return;

  const redeemHex = assets.redeemFromSignatureScript(manifest.tokenSignatureScriptHex);
  const verified = assets.verifyTokenInputRedeem({ descriptor: validated, redeemHex });
  const tokenIn = tokenIns[0];
  check("tokenInputRedeemMatchesUtxo", verified.p2shSpkHex === tokenIn.utxo.scriptPublicKey.scriptHex.toLowerCase(), "revealed redeem reproduces the token UTXO's P2SH");
  check(
    "tokenInputOwnedByController",
    verified.state.ownerIdentifier === manifest.controller.covenantId && verified.state.identifierType === OWNER_SCHEMES.COVENANT_ID && !verified.state.isMinter,
    "position owned via covenant-id/v1"
  );

  const positionBefore = verified.state.amount;
  const spend = digits(manifest.accounting.token.spendAmount, "accounting.token.spendAmount");
  const positionAfter = digits(manifest.accounting.token.positionAfter, "accounting.token.positionAfter");
  check(
    "tokenConservation",
    positionBefore.toString() === manifest.accounting.token.positionBefore && positionBefore === spend + positionAfter && spend > 0n,
    `${positionBefore} == ${spend} + ${positionAfter}`
  );

  /* reconstruct both continuation outputs from the template + declared states */
  const selfState = kcc20.encodeState({ ownerIdentifier: manifest.controller.covenantId, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: positionAfter, isMinter: false });
  const recipState = kcc20.encodeState({ ownerIdentifier: manifest.policy.recipient, identifierType: OWNER_SCHEMES.P2PK, amount: spend, isMinter: false });
  const selfSpk = kcc20.p2shSpkHex(kcc20.reconstructRedeem(verified.prefixHex, selfState, verified.suffixHex));
  const recipSpk = kcc20.p2shSpkHex(kcc20.reconstructRedeem(verified.prefixHex, recipState, verified.suffixHex));
  check("selfContinuationReconstructed", tokenOuts[0].scriptPublicKey.scriptHex.toLowerCase() === selfSpk, "family output 0 == template(self state)");
  check("recipientContinuationReconstructed", tokenOuts[1].scriptPublicKey.scriptHex.toLowerCase() === recipSpk, "family output 1 == template(recipient state)");

  /* KAS carry rules: the token family's KAS never leaks into the fee or the reserve */
  const carryIn = BigInt(tokenIn.utxo.amount);
  const selfCarry = BigInt(tokenOuts[0].value);
  const recipCarry = BigInt(tokenOuts[1].value);
  check(
    "tokenFamilyKasNoLeak",
    selfCarry + recipCarry >= carryIn && selfCarry.toString() === manifest.accounting.kas.tokenSelfCarryKas && recipCarry.toString() === manifest.accounting.kas.tokenRecipientCarryKas,
    "self + recipient carry >= token input KAS"
  );

  /* agent authority: leaf under the LIVE predecessor root, caps, budget, allowlist, successor fold */
  const policy = manifest.policy.agentPolicy ? normalizeTokenAgentPolicyV6(manifest.policy.agentPolicy) : null;
  check("agentPolicyPresent", !!policy, "agent policy carried");
  if (!policy) return;
  const proof = manifest.policy.agentProof;
  check(
    "agentPolicyCommitted",
    !!proof && proof.root === before.agentRoot && verifyTokenAgentProofV6({ root: before.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) }),
    "leaf proven under the predecessor agentRoot"
  );
  check("spendWithinCap", spend <= policy.tokenMaxPerSpend, `spend ${spend} <= cap ${policy.tokenMaxPerSpend}`);
  const periods = digits(manifest.policy.periodsElapsed, "policy.periodsElapsed");
  const newStart = periods >= 1n ? policy.periodStartDaa + periods * policy.periodLengthDaa : policy.periodStartDaa;
  const newTokenSpent = periods >= 1n ? spend : policy.tokenPeriodSpent + spend;
  /* a spend moves NO KAS consideration: the KAS period accounting must not advance */
  const newKasSpent = periods >= 1n ? 0n : policy.kasPeriodSpent;
  check("spendWithinBudget", newTokenSpent <= policy.tokenPeriodBudget, `period spent ${newTokenSpent} <= budget ${policy.tokenPeriodBudget}`);
  check("rolloverLock", periods >= 1n ? BigInt(frozen.lockTime) === newStart : BigInt(frozen.lockTime) === 0n, "lockTime == rollover period start (or 0)");
  check("lockTimeDeclared", manifest.policy.lockTime === frozen.lockTime.toString(), "declared lockTime == frozen lockTime");
  const newPolicy = { ...manifest.policy.agentPolicy, periodStartDaa: newStart.toString(), tokenPeriodSpent: newTokenSpent.toString(), kasPeriodSpent: newKasSpent.toString() };
  check("successorRootDerived", foldTokenAgentPolicyV6(newPolicy, proof.siblingsHex, BigInt(proof.pathBits)) === after.agentRoot, "successor agentRoot == fold(advanced leaf) up the same co-path");
  check("reserveWithinAgentCap", digits(manifest.accounting.kas.reserveConsumed, "accounting.kas.reserveConsumed") <= policy.agentMaxFeePerTx, "reserve consumed <= agentMaxFeePerTx");
  check("carryWithinAgentCap", recipCarry <= policy.agentMaxCarryKas, "recipient carry <= agentMaxCarryKas");
  const rp = manifest.policy.recipientProof;
  check(
    "recipientAllowlisted",
    !!rp && rp.root === policy.agentRecipientRoot && verifyRecipientProof({ root: rp.root, recipient: manifest.policy.recipient, siblingsHex: rp.siblingsHex, pathBits: BigInt(rp.pathBits) }),
    "recipient proven under the agent's recipient root"
  );
  void fee;
}

/*
 * The six owner control operations. Each one may change EXACTLY its own
 * field(s); every other state field must be preserved, and any external
 * funding must land in exactly the domain the operation names.
 */
function verifyOwnerControlV6({ manifest, check, before, after, family, inputs, outputs }) {
  const action = manifest.action.sdkAction;
  check("declaredOpSelector", manifest.policy.opSelector === (ownGet(ACTIONS, action) || {}).opSelector, "the build's covenant op selector == the action table");
  check("noTokenMovement", !inputs.some((i) => i.utxo.covenantId === family) && !outputs.some((o) => o.covenant && o.covenant.covenantId === family), "owner control ops never move tokens");
  const funding = digits(manifest.policy.externalFunding ?? "0", "policy.externalFunding");
  const reserveDelta = after.feeReserve - before.feeReserve;
  const principalDelta = after.swapPrincipal - before.swapPrincipal;
  const nonceDelta = after.policyNonce - before.policyNonce;

  const preserved = (fields) => fields.every((f) => before[f] === after[f]);
  switch (action) {
    case "ownerSetAgentRoot":
      check("stateEquations", nonceDelta === 1n && reserveDelta === 0n && principalDelta === 0n && preserved(["swapRoot", "paused"]) && before.agentRoot !== after.agentRoot, "agentRoot replaced; nonce +1; reserve/principal/swapRoot/paused preserved");
      check("noExternalFunding", funding === 0n, "a root change funds nothing");
      break;
    case "ownerSetSwapRoot":
      check("stateEquations", nonceDelta === 1n && reserveDelta === 0n && principalDelta === 0n && preserved(["agentRoot", "paused"]) && before.swapRoot !== after.swapRoot, "swapRoot replaced; nonce +1; reserve/principal/agentRoot/paused preserved");
      check("noExternalFunding", funding === 0n, "a root change funds nothing");
      break;
    case "ownerTopUpReserve":
      check("stateEquations", nonceDelta === 0n && principalDelta === 0n && preserved(["agentRoot", "swapRoot", "paused"]) && reserveDelta > 0n, "fee reserve increases only; nonce/principal/roots/paused preserved");
      check("fundingLandsInReserve", reserveDelta === funding && funding > 0n, `reserve +${reserveDelta} == declared external funding ${funding}`);
      break;
    case "ownerFundSwapPrincipal":
      check("stateEquations", nonceDelta === 0n && reserveDelta === 0n && preserved(["agentRoot", "swapRoot", "paused"]) && principalDelta > 0n, "swap principal increases only; nonce/reserve/roots/paused preserved");
      check("fundingLandsInPrincipal", principalDelta === funding && funding > 0n, `principal +${principalDelta} == declared external funding ${funding}`);
      break;
    case "ownerPause":
      check("stateEquations", nonceDelta === 0n && reserveDelta === 0n && principalDelta === 0n && preserved(["agentRoot", "swapRoot"]) && before.paused === 0n && after.paused === 1n, "paused 0 -> 1; every other field preserved");
      check("noExternalFunding", funding === 0n, "pausing funds nothing");
      break;
    case "ownerUnpause":
      check("stateEquations", nonceDelta === 0n && reserveDelta === 0n && principalDelta === 0n && preserved(["agentRoot", "swapRoot"]) && before.paused === 1n && after.paused === 0n, "paused 1 -> 0; every other field preserved");
      check("noExternalFunding", funding === 0n, "unpausing funds nothing");
      break;
    default:
      check("ownerActionKnown", false, `unhandled owner action ${JSON.stringify(action)} — failing closed`);
  }
}

/*
 * ownerRecover (terminal): BOTH KAS domains return to the owner key in one
 * output, and any token position becomes an owner-owned continuation
 * reconstructed from the descriptor template.
 */
function verifyRecoverV6({ manifest, validated, check, inputs, outputs, before, family }) {
  const payout = before.feeReserve + before.swapPrincipal;
  check(
    "payoutToOwner",
    outputs[0].covenant === null &&
      outputs[0].scriptPublicKey.scriptHex.toLowerCase() === p2pkSpk(manifest.controller.owner) &&
      BigInt(outputs[0].value) === payout &&
      outputs[0].value === manifest.accounting.kas.terminalPayout,
    "output 0 pays feeReserve + swapPrincipal to the owner key"
  );
  check("noSuccessor", !outputs.some((o) => o.covenant && o.covenant.covenantId === manifest.controller.covenantId), "terminal: no controller successor output");
  const tokenIns = inputs.filter((i) => i.utxo.covenantId === family);
  const tokenOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === family);
  check("familyShape", tokenIns.length <= 1 && tokenOuts.length === tokenIns.length, "0 or 1 token input with a matching owner-owned continuation");
  if (tokenIns.length === 1) {
    const redeemHex = assets.redeemFromSignatureScript(manifest.tokenSignatureScriptHex);
    const verified = assets.verifyTokenInputRedeem({ descriptor: validated, redeemHex });
    check("tokenInputRedeemMatchesUtxo", verified.p2shSpkHex === tokenIns[0].utxo.scriptPublicKey.scriptHex.toLowerCase(), "revealed redeem reproduces the token UTXO's P2SH");
    const ownerState = kcc20.encodeState({ ownerIdentifier: manifest.controller.owner, identifierType: OWNER_SCHEMES.P2PK, amount: verified.state.amount, isMinter: false });
    const ownerSpk = kcc20.p2shSpkHex(kcc20.reconstructRedeem(verified.prefixHex, ownerState, verified.suffixHex));
    check(
      "tokensReturnToOwner",
      tokenOuts[0].scriptPublicKey.scriptHex.toLowerCase() === ownerSpk && verified.state.amount.toString() === manifest.accounting.token.recoveredToOwner,
      "the entire token amount moves to the owner key"
    );
  }
}

/*
 * v0.6-labelled deposit verification — the same rules the v0.5 deposit
 * verifier applies (the mechanics ARE v0.5), re-stated against the v0.6
 * controller pins: the user's revealed position reconstructed through the
 * descriptor template, exact token conservation, family KAS conserved,
 * exact fee, and NO controller or foreign covenant input.
 */
function verifyDepositV6(manifest, validated, check, frozen, fee) {
  check("depositMechanics", manifest.policy.depositMechanics === "policyvault-0.5", "deposit mechanics declared (v0.5 mechanics under the v0.6 lineage)");
  check("descriptorFamily", validated.tokenCovenantId === manifest.controller.tokenCovenantId, "descriptor family == controller pin");
  const tpl = validated.acceptedTransferTemplates[manifest.asset.templateIndex];
  check(
    "templatePin",
    !!tpl && tpl.templateVmHashBlake2b256 === manifest.controller.templateVmHashBlake2b256 && tpl.prefixLen === manifest.controller.templateGeometry.prefixLen && tpl.suffixLen === manifest.controller.templateGeometry.suffixLen,
    "descriptor template == controller pin"
  );
  const inputs = frozen.inputs;
  const outputs = frozen.outputs;
  const family = manifest.controller.tokenCovenantId;
  const tokenIns = inputs.filter((i) => i.utxo.covenantId === family);
  const tokenOuts = outputs.filter((o) => o.covenant && o.covenant.covenantId === family);
  check(
    "noControllerOrForeignInputs",
    inputs.every((i) => i.utxo.covenantId === null || i.utxo.covenantId === family) && !inputs.some((i) => i.utxo.covenantId === manifest.controller.covenantId),
    "only the user's token input and plain fuel"
  );
  const before = digits(manifest.accounting.token.positionBefore, "positionBefore");
  const deposit = digits(manifest.accounting.token.deposit, "deposit");
  const remainder = digits(manifest.accounting.token.remainderToUser, "remainderToUser");
  check("tokenConservation", deposit > 0n && before === deposit + remainder, `${before} == ${deposit} + ${remainder}`);
  check("familyShape", tokenIns.length === 1 && tokenOuts.length === (remainder > 0n ? 2 : 1), "1 token input; deposit (+ remainder) outputs");
  if (tokenIns.length === 1 && tpl) {
    const userPk = hex(manifest.policy.userPk, 32, "policy.userPk");
    check("userPositionEnvelope", tokenIns[0].utxo.scriptPublicKey.scriptHex.length === 70, "token input is a version-0 P2SH");
    const declared = manifest.policy.tokenNewStates;
    check(
      "depositOwnerIsController",
      declared[0] && declared[0].ownerIdentifier === manifest.controller.covenantId && declared[0].identifierType === OWNER_SCHEMES.COVENANT_ID && declared[0].amount === deposit.toString() && declared[0].isMinter === false,
      "continuation 0 owned by the controller covenant id with the deposit amount"
    );
    if (remainder > 0n) {
      check(
        "remainderOwnerIsUser",
        declared[1] && declared[1].ownerIdentifier === userPk && declared[1].identifierType === OWNER_SCHEMES.P2PK && declared[1].amount === remainder.toString(),
        "remainder returns to the user key"
      );
    }
    const carryIn = BigInt(tokenIns[0].utxo.amount);
    const carryOut = tokenOuts.reduce((s, o) => s + BigInt(o.value), 0n);
    check("familyKasConserved", carryIn === carryOut && carryIn.toString() === manifest.accounting.kas.positionKas, "family KAS in == out");
  }
  void fee;
}

module.exports = {
  CONTROLLER_MANIFEST_VERSION_1,
  CONTRACT_VERSION_V6,
  ACTIONS,
  SWAP_ACTIONS,
  VERIFIED_STATEMENT,
  buildControllerIntentManifestV6,
  verifyControllerIntentManifestV6,
  canonicalJsonStringify
};
