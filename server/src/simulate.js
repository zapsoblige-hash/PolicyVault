"use strict";

/*
 * Dry-run / simulation for v0.4 wallet-request building (completion-
 * standard surface 16; docs/postlaunch/platform-agent-api-spec.md).
 *
 * Runs the EXACT SAME pipeline the real POST /wallet/v4/requests route
 * runs — the SAME exported SDK planner/authorizer/builder
 * (sdk/src/wallet-requests-v4.js planV4/assertSignerAuthorizedV4, the SAME
 * sdk/src/vault-builders-v4.js buildV4Transaction, the SAME governance
 * classifier and risk composer server/src/governance.js
 * classifyActionV4 / core/risk evaluateRisk, the SAME core/intent/bridge
 * manifest derivation) — but PERSISTS NOTHING: no saveRequest, no
 * saveEvaluation, no createProposal/markProposalConsumed, no appendAudit.
 * Every store write those real code paths perform is deliberately NOT
 * called here; this module only READS (manifest, org controls) and
 * invokes PURE/offline functions (the SDK builder does no RPC/store I/O —
 * see vault-builders-v4.js's own header comment).
 *
 * ANTI-BLOAT: no policy/financial semantics are reimplemented — every
 * consequential decision (authorization, governance classification, risk
 * composition, fee/successor derivation, manifest verification) is the
 * REAL function call, not a rebuilt approximation. This module is a thin
 * reporting shell around the existing pipeline.
 *
 * VM preflight is INTENTIONALLY SKIPPED: real preflight
 * (wallet-requests-v4.js runPreflight) validates Schnorr signatures over
 * the frozen transaction, and a dry run never asks the caller to produce
 * one. Fee/mass and successor-state correctness are still exact (the REAL
 * silverc compiler + REAL call encoder run inside buildV4Transaction) —
 * only the signature-verification stage of preflight is not exercised.
 * This is stated honestly rather than oversold (progress-reporting
 * discipline, CLAUDE.md).
 */

const { loadManifestV4 } = require("../../sdk/src/manifest-v4");
const { resolveV4Abi, stateToJsonV4 } = require("../../sdk/src/vault-state-v4");
const { buildV4Transaction } = require("../../sdk/src/vault-builders-v4");
const { resolveAddressIdentity, requiredAddressPrefix } = require("../../sdk/src/address-identity");
const { sompiToKas } = require("../../sdk/src/amounts");
const wr4 = require("../../sdk/src/wallet-requests-v4");
const { deriveAndVerify } = require("../../core/intent/bridge/derive");
const { HIGH_LEVEL_TO_SDK } = require("../../core/intent");
const governance = require("./governance");
const { controlsForVault } = require("./org-controls");
const { evaluateRisk } = require("../../core/risk");
const { buildAdaptersFromConfig } = require("./risk-adapters");
const { buildRiskIntent, intentHashOf } = require("./risk");

const SIMULATION_SCHEMA = "policyvault-simulation/v1";

function fail(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

/* Same structured summary shape as wallet-requests-v4.js reviewForBuild,
 * reconstructed here from the SAME build.accounting the real path uses
 * (that function itself is not exported — see the file header). Purely a
 * KAS-formatting presenter; no financial arithmetic happens here. */
function reviewFromBuild(build) {
  const acc = build.accounting;
  const out = {
    feeKas: sompiToKas(BigInt(acc.fee)),
    feeSompi: acc.fee,
    computeBudget: build.computeBudget,
    protectedBeforeKas: sompiToKas(BigInt(acc.predecessorProtected)),
    reserveBeforeKas: sompiToKas(BigInt(acc.predecessorFeeReserve))
  };
  if (!build.successorState) {
    out.terminal = "VAULT CLOSED — protected value + fee reserve return to the owner wallet";
    out.recoveredKas = sompiToKas(BigInt(acc.terminalPayout));
    out.protectedAfterKas = "0";
    out.reserveAfterKas = "0";
  } else {
    out.protectedAfterKas = sompiToKas(BigInt(acc.successorProtected));
    out.reserveAfterKas = sompiToKas(BigInt(acc.successorFeeReserve));
    out.reserveConsumedKas = sompiToKas(BigInt(acc.reserveConsumed));
    out.externalFuelKas = sompiToKas(BigInt(acc.externalIn));
  }
  if (build.payment) {
    out.paymentKas = sompiToKas(BigInt(build.payment.value));
    out.fundingMode = build.hasFuelInput ? "FUEL-FUNDED" : "RESERVE-FUNDED";
  }
  return out;
}

/*
 * Simulate one v0.4 transition request (action against an EXISTING vault
 * — mirrors POST /wallet/v4/requests's body exactly; genesis/create
 * simulation is out of scope for v1 — see the spec doc). Never throws for
 * a SUBSTANTIVE "would this succeed" outcome (those become ok:false with
 * refusalReason); throws only for malformed input (400) — the SAME split
 * server/src/api.js already uses for the real route's own input checks.
 */
async function simulateWalletRequestV4(config, { vaultId, action, params, signerAddress }) {
  if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) throw fail(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
  if (typeof action !== "string" || !action) throw fail(400, "BAD_ACTION", "action is required");
  const requiredPrefix = `${requiredAddressPrefix(config.networkId)}:`;
  if (typeof signerAddress !== "string" || !signerAddress.startsWith(requiredPrefix)) {
    throw fail(400, "BAD_SIGNER", `signerAddress must be a ${config.networkId} address (${requiredPrefix}...)`);
  }
  const safeParams = params && typeof params === "object" ? params : {};

  const base = { schemaVersion: SIMULATION_SCHEMA, vaultId, action, network: config.networkId };
  let governanceReport = null;
  let riskReport = null;

  try {
    const manifest = await loadManifestV4(config, vaultId);
    if (!manifest) throw fail(422, "BUILD_FAILED", `no v0.4 manifest for vault ${vaultId}`);
    resolveV4Abi(manifest.contractVersion); // fails closed on a non-v0.4-family contract
    if (!manifest.live) throw fail(422, "VAULT_TERMINAL", `vault is ${manifest.status} (closed) — it is read-only history and accepts no further operations`);

    const requiredRole = wr4.ROLE_BY_ACTION[action];
    if (!requiredRole) throw fail(422, "BUILD_FAILED", `unknown action ${action} — failing closed`);

    // Instant hosted-layer suspend (surface 21 residual): the dry run
    // reports the SAME refusal the real build route enforces (an honest
    // simulation must not say ok:true for an operation the real route
    // refuses). Coordination control only — the refusal text carries the
    // covenant-honesty notice verbatim.
    if (requiredRole === "agent") {
      const { checkAgentSuspension, suspendedError } = require("./agent-suspensions");
      const agentPks = [];
      if (typeof safeParams.agentPk === "string" && /^[0-9a-f]{64}$/.test(safeParams.agentPk)) agentPks.push(safeParams.agentPk);
      try {
        agentPks.push(resolveAddressIdentity(config, signerAddress).xOnlyPubkey);
      } catch {
        /* the authorization stage below reports the precise signer error */
      }
      const check = await checkAgentSuspension(config, vaultId, agentPks);
      if (check.suspended) throw suspendedError(check, "simulate this operation (the real build route refuses identically)");
    }

    // ---- governance classification + risk composition (REPORT ONLY) ----
    const gate = governance.classifyActionV4(config, manifest, action, safeParams); // pure; throws on malformed params
    const breakGlass = gate.breakGlass === true;
    if (!gate.governed) {
      governanceReport = { governed: false, breakGlass };
    } else {
      const { controls } = await controlsForVault(config, vaultId);
      const wouldRequireProposal = gate.classification === "EXPANSION";
      governanceReport = {
        governed: true,
        classification: gate.classification,
        codes: gate.codes,
        wouldRequireProposal,
        quorum: controls.governance.quorum ?? { approvers: [], m: 1, note: "owner-only (no organization quorum configured)" },
        delayMs: controls.governance.delayMs
      };
    }
    if (breakGlass) {
      riskReport = { skipped: true, breakGlass: true };
    } else {
      // The real route risk-screens EVERY known action once break-glass is
      // ruled out — unconditional on governance status (server/src/api.js's
      // `if (!breakGlass) { ... riskGate = await riskSvc.gateOperationRisk(...) }`
      // runs regardless of `gate.governed`; e.g. agentSpend/ownerTopUp are
      // governed:false but still screened). Mirror that exactly.
      const { orgId, controls } = await controlsForVault(config, vaultId);
      const hasControls = (controls.risk.adapters ?? []).length > 0 || controls.risk.reviewRequired === true || (controls.risk.onEmpty !== undefined && controls.risk.onEmpty !== "ALLOW");
      if (!hasControls) {
        riskReport = { skipped: true };
      } else {
        let signerXOnlyForRisk = null;
        try {
          signerXOnlyForRisk = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
        } catch {
          signerXOnlyForRisk = null;
        }
        const intent = buildRiskIntent({
          config, vaultId, action, params: safeParams, signerAddress, signerXOnly: signerXOnlyForRisk,
          sdkAction: HIGH_LEVEL_TO_SDK[action] ?? action
        });
        const adapters = buildAdaptersFromConfig(controls.risk);
        const composeConfig = {
          onAdapterError: controls.risk.onAdapterError,
          ...(controls.risk.onEmpty !== undefined ? { onEmpty: controls.risk.onEmpty } : {}),
          ...(controls.risk.timeoutMs !== undefined ? { timeoutMs: controls.risk.timeoutMs } : {})
        };
        const context = { orgId, riskPolicy: { reviewRequired: controls.risk.reviewRequired === true } };
        const result = await evaluateRisk({ adapters, intent, context, config: composeConfig });
        riskReport = { skipped: false, decision: result.decision, codes: result.codes, intentHash: intentHashOf(intent) };
      }
    }

    // ---- plan + authorize (REAL functions; never reimplemented) ----
    const plan = wr4.planV4(config, manifest, action, safeParams);
    if (plan.role !== requiredRole) throw fail(422, "BUILD_FAILED", `role map disagreement for ${action} — failing closed`);
    wr4.assertSignerAuthorizedV4(config, { role: requiredRole, signerAddress, template: manifest.template, manifest, action, agentPk: plan.agentPk });
    if (plan.role === "agent" && manifest.status !== "ACTIVE") {
      throw fail(422, "BUILD_FAILED", `vault status is ${manifest.status} — agent operations need ACTIVE`);
    }

    const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
    const isSpend = plan.sdkAction === "agentSpend";
    const hasFuel = safeParams.fuel !== undefined && safeParams.fuel !== null;
    if (!isSpend && !hasFuel) {
      throw fail(422, "BUILD_FAILED", `${action} pins every covenant value, so its network fee must come from an ordinary fuel UTXO — provide params.fuel`);
    }

    // ---- build (REAL SDK builder; pure/offline — no RPC, no store I/O) ----
    const abi = resolveV4Abi(manifest.contractVersion);
    const build = buildV4Transaction({
      config,
      contractVersion: abi.version,
      templateInput: { owner: manifest.template.owner, vaultId: manifest.vaultId },
      stateInput: stateToJsonV4(manifest.live.state),
      action: plan.sdkAction,
      params: plan.sdkParams,
      chain: {
        predecessorOutpoint: manifest.live.outpoint,
        predecessorValue: (manifest.live.state.protectedValue + manifest.live.state.feeReserve).toString(),
        covenantId: manifest.live.covenantId,
        ...(hasFuel ? { fuel: safeParams.fuel } : {})
      },
      changeXOnly: signerXOnly
    });
    if (build.successorScriptSha256 !== null && manifest.live.scriptSha256 && build.predecessorStateId !== manifest.live.stateId) {
      throw fail(409, "STALE", "predecessor drift at build — failing closed");
    }

    // ---- intent-manifest derivation + verification (NOT persisted) ----
    const { manifest: intentManifest, verification } = deriveAndVerify({ build });

    const aboveThreshold = build.aboveThreshold === true;
    return {
      ...base,
      ok: true,
      governance: governanceReport,
      risk: riskReport,
      review: reviewFromBuild(build),
      intent: {
        manifestHash: intentManifest.manifestHash,
        verdict: verification.verdict,
        ok: verification.ok === true,
        failureCodes: [...new Set((verification.failures ?? []).map((f) => f.code))].sort()
      },
      wouldRequire: {
        approvals: aboveThreshold ? { required: manifest.live.state.approvalM.toString() } : null,
        proposal: governanceReport ? governanceReport.wouldRequireProposal === true : false,
        riskRelease: riskReport && riskReport.skipped !== true ? riskReport.decision === "REVIEW" : false
      },
      vmPreflight: { skipped: true, reason: "requires a real signature over the frozen transaction, which a dry run never asks the caller to produce" }
    };
  } catch (error) {
    if (error.status && error.status < 400) throw error; // never expected; defensive
    if (error.status === 400) throw error; // malformed input: real HTTP error, not a simulated outcome
    return {
      ...base,
      ok: false,
      governance: governanceReport,
      risk: riskReport,
      refusalReason: { status: error.status || 500, code: error.code || "SIMULATION_FAILED", message: error.message }
    };
  }
}

module.exports = { SIMULATION_SCHEMA, simulateWalletRequestV4 };
