"use strict";

/*
 * PolicyVault Intent-Manifest SDK DERIVATION BRIDGE (v1).
 *
 * This is the ONE core module permitted to depend on the SDK. It maps the
 * output of the REAL v0.4 offline transaction builders
 * (sdk/src/vault-builders-v4.js: buildV4Transaction / buildCreateV4) — the
 * exact objects the production build pipeline emits, whose consensus bytes
 * are VM-proven by tests/vm/tests/v4_sdk_integration.rs — into the
 * structured inputs of core/intent buildIntentManifest, then (optionally)
 * runs the fail-closed verifier. It lets a Transaction Intent Manifest be
 * produced from an ACTUAL builder output rather than a hand-built fixture,
 * closing the v0.2-boundVaultId-class gap where an in-process fixture can
 * diverge from what the builder physically emits.
 *
 * Direction of trust: the SDK builder is authoritative for consensus
 * semantics (script/txId/sighash/fee/successor). The bridge NEVER invents
 * consensus facts; it only reshapes the builder's own outputs into the
 * manifest schema and lets buildIntentManifest + verifyIntentManifest prove
 * the transaction's declared meaning equals the requested meaning. Anything
 * missing, malformed, or version-unknown FAILS CLOSED.
 *
 * SDK dependencies are READ-ONLY and imported by RELATIVE PATH (never a
 * copy): they load offline (no wasm/RPC/spawn at import time) —
 *   - vault-state-v4.js : the supported covenant-version tags
 *   - agent-merkle-v4.js : foldAgentPolicyV4 (single-leaf root cross-check)
 * The heavy consensus toolchain (silverc, pv_call_encoder, pv_tx_probe,
 * kaspa-wasm) is exercised only when a CALLER actually runs the builders;
 * this bridge itself is pure and offline.
 */

const { buildIntentManifest, p2pkScriptHex } = require("../manifest");
const { verifyIntentManifest } = require("../verify");

/* SDK (read-only, relative-path) — the single core↔sdk seam. */
const { CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1 } = require("../../../sdk/src/vault-state-v4");
const { foldAgentPolicyV4 } = require("../../../sdk/src/agent-merkle-v4");

/* Build contract versions this bridge understands. Mirrors the manifest's
 * SUPPORTED_COVENANT_VERSIONS (policyvault-0.4 family). Unknown versions
 * fail closed — never routed to a default. */
const SUPPORTED_BUILD_VERSIONS = Object.freeze([CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1]);

/* The 9 v0.4 agent-policy leaf fields, in agent-merkle-v4 order. */
const AGENT_POLICY_FIELDS = Object.freeze([
  "agentPk",
  "maxPerSpend",
  "periodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "periodSpent",
  "approvalThreshold",
  "agentMaxFeePerTx",
  "agentRecipientRoot"
]);

const CANONICAL_DIGITS_RE = /^(0|[1-9][0-9]*)$/;

function refuse(code, message) {
  const e = new Error(`intent-bridge: ${message}`);
  e.code = code;
  throw e;
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/* A builder emits canonical base-10 digit strings for every sompi/DAA
 * quantity (sdk/src/amounts.js). The bridge only ever does BigInt math on
 * such strings; anything else (a float, a number, a malformed string that
 * slipped through a tampered build object) is refused before arithmetic. */
function toBigIntStrict(value, field) {
  if (typeof value !== "string" || !CANONICAL_DIGITS_RE.test(value)) {
    refuse("BRIDGE_VALUE_INVALID", `${field} must be a canonical base-10 digit string, got ${typeof value === "string" ? JSON.stringify(value) : typeof value}`);
  }
  return BigInt(value);
}

function requireField(obj, key, field) {
  if (!isPlainObject(obj) || !Object.prototype.hasOwnProperty.call(obj, key)) {
    refuse("BRIDGE_BUILD_INVALID", `${field} is missing from the builder output`);
  }
  return obj[key];
}

/* ------------------------------------------------------------------ */
/* transaction reconstruction                                          */
/* ------------------------------------------------------------------ */

/*
 * The decoded transaction document the manifest embeds is the builder's
 * OWN canonical frozen serialization (sdk/src/frozen-tx-v3.js
 * canonicalFrozenTxJson — the exact bytes approvers sign against and the
 * fee/txId are computed over), with the authoritative txId (from the real
 * pv_tx_probe, via describeFrozenTx) prepended. The bridge does not rebuild
 * or re-order the transaction — a manifest must describe the transaction as
 * it will actually broadcast.
 */
function transactionDoc(build) {
  const txId = requireField(build, "txId", "build.txId");
  const canonicalJson = requireField(build, "frozenCanonicalJson", "build.frozenCanonicalJson");
  if (typeof canonicalJson !== "string") {
    refuse("BRIDGE_BUILD_INVALID", "build.frozenCanonicalJson must be the builder's canonical serialization string");
  }
  let frozen;
  try {
    frozen = JSON.parse(canonicalJson);
  } catch {
    refuse("BRIDGE_BUILD_INVALID", "build.frozenCanonicalJson is not valid JSON");
  }
  if (!isPlainObject(frozen) || !Array.isArray(frozen.inputs) || !Array.isArray(frozen.outputs)) {
    refuse("BRIDGE_BUILD_INVALID", "build.frozenCanonicalJson is not a frozen transaction document");
  }
  /* txId first, then the exact frozen fields — the manifest schema is a
   * CLOSED key set, so the shape must match validateTransactionShape. */
  return {
    txId,
    version: frozen.version,
    inputs: frozen.inputs,
    outputs: frozen.outputs,
    lockTime: frozen.lockTime,
    subnetworkId: frozen.subnetworkId,
    gas: frozen.gas,
    payload: frozen.payload
  };
}

/* ------------------------------------------------------------------ */
/* effect classification (derived from real builder facts)             */
/* ------------------------------------------------------------------ */

/*
 * Classify every input/output kind, in transaction order, from the
 * builder's OWN facts — never a guess:
 *   - an input is `covenant` iff its UTXO carries a covenantId (the
 *     predecessor), else `external` (ordinary fuel/funding);
 *   - a covenant-bound output is the `successor` (transition) or
 *     `genesisVault` (genesis);
 *   - the remaining outputs are identified by the builder's realized
 *     recipient/payout/change facts (payment recipient, terminal payout
 *     value, genesis change index).
 * The manifest re-checks that each `covenant`/`successor`/`genesisVault`
 * classification agrees with the transaction's covenant bindings; a
 * misclassification fails closed there.
 */
function classifyEffects(build, txDoc) {
  const inputs = txDoc.inputs.map((input, i) => {
    const utxo = input && input.utxo;
    if (!isPlainObject(utxo)) refuse("BRIDGE_BUILD_INVALID", `transaction input ${i} is missing its utxo`);
    return utxo.covenantId == null ? "external" : "covenant";
  });

  const action = build.action;
  const outputs = txDoc.outputs.map((output, i) => {
    const bound = output && output.covenant != null;
    if (build.kind === "genesis") {
      if (bound) return "genesisVault";
      return i === build.changeIndex ? "change" : "agentFuel";
    }
    if (bound) return "successor";
    if (action === "agentSpend") {
      const pay = build.payment;
      if (
        isPlainObject(pay) &&
        output.scriptPublicKey &&
        output.scriptPublicKey.scriptHex === p2pkScriptHex(pay.recipient) &&
        output.value === String(pay.value)
      ) {
        return "payment";
      }
      return "change";
    }
    if (action === "ownerRecover") {
      if (output.value === String(build.accounting.terminalPayout)) return "recoverPayout";
      return "change";
    }
    /* owner mutation ops: the only non-covenant output is fee change. */
    return "change";
  });

  return { inputs, outputs };
}

/* ------------------------------------------------------------------ */
/* agent-policy leaf mapping (agentSpend only)                         */
/* ------------------------------------------------------------------ */

/* The authenticated predecessor leaf, straight from the builder's real
 * covenant-call extra (build.callExtra carries the exact policy the
 * builder proved against the live agentRoot). */
function policyBeforeFromBuild(build) {
  const ce = build.callExtra;
  if (!isPlainObject(ce)) refuse("BRIDGE_BUILD_INVALID", "an agentSpend build must carry callExtra (the proven agent leaf)");
  const leaf = {};
  for (const field of AGENT_POLICY_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(ce, field)) {
      refuse("BRIDGE_BUILD_INVALID", `build.callExtra is missing agent-policy field ${field}`);
    }
    leaf[field] = ce[field];
  }
  return leaf;
}

/*
 * The post-spend leaf under the EXACT covenant single-leaf rollover rule
 * (sdk/src/vault-transitions-v4.js agentSpendSuccessorV4 / the compiled
 * covenant): a fresh period (periodsElapsed >= 1) advances periodStartDaa
 * by periodsElapsed * periodLengthDaa and resets periodSpent to the pay
 * amount; otherwise periodSpent accumulates. Every other field is
 * preserved. The result is CROSS-CHECKED by folding it up the builder's
 * own co-path and requiring it to reproduce the real successor agentRoot —
 * so the derived leaf is provably the exact one the builder committed, not
 * a plausible reconstruction.
 */
function policyAfterFromBuild(build, policyBefore) {
  const ce = build.callExtra;
  const periods = toBigIntStrict(ce.periodsElapsed, "build.callExtra.periodsElapsed");
  const pay = toBigIntStrict(ce.payAmount, "build.callExtra.payAmount");
  const periodStartDaa = toBigIntStrict(policyBefore.periodStartDaa, "policyBefore.periodStartDaa");
  const periodLengthDaa = toBigIntStrict(policyBefore.periodLengthDaa, "policyBefore.periodLengthDaa");
  const periodSpent = toBigIntStrict(policyBefore.periodSpent, "policyBefore.periodSpent");

  let newStart = periodStartDaa;
  let newSpent = periodSpent + pay;
  if (periods >= 1n) {
    newStart = periodStartDaa + periods * periodLengthDaa;
    newSpent = pay;
  }
  const policyAfter = { ...policyBefore, periodStartDaa: newStart.toString(), periodSpent: newSpent.toString() };

  /* single-leaf fold cross-check against the REAL successor root */
  const siblingsHex = String(ce.policySiblings ?? "").toLowerCase();
  const pathBits = toBigIntStrict(String(ce.policyPathBits), "build.callExtra.policyPathBits");
  let foldedRoot;
  try {
    foldedRoot = foldAgentPolicyV4(policyAfter, siblingsHex, pathBits);
  } catch (e) {
    refuse("BRIDGE_LEAF_FOLD_FAILED", `single-leaf fold of the derived successor policy failed: ${e.message}`);
  }
  const successorRoot = build.successorState && build.successorState.agentRoot;
  if (foldedRoot === null || foldedRoot !== successorRoot) {
    refuse(
      "BRIDGE_LEAF_FOLD_MISMATCH",
      "the derived successor agent-policy leaf does not fold to the builder's successor agentRoot — refusing (the bridge never emits a leaf it cannot tie to the real committed root)"
    );
  }
  return policyAfter;
}

/* ------------------------------------------------------------------ */
/* accounting                                                          */
/* ------------------------------------------------------------------ */

/* A transition build already carries the exact 11-field §E4 accounting. */
const ACCOUNTING_FIELDS = Object.freeze([
  "predecessorProtected",
  "predecessorFeeReserve",
  "payAmount",
  "reserveConsumed",
  "externalIn",
  "externalOut",
  "fee",
  "successorProtected",
  "successorFeeReserve",
  "successorTotal",
  "terminalPayout"
]);

function transitionAccounting(build) {
  const acc = build.accounting;
  if (!isPlainObject(acc)) refuse("BRIDGE_BUILD_INVALID", "a transition build must carry accounting");
  const out = {};
  for (const field of ACCOUNTING_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(acc, field)) {
      refuse("BRIDGE_BUILD_INVALID", `build.accounting is missing ${field}`);
    }
    out[field] = acc[field];
  }
  return out;
}

/*
 * Genesis (createVault) is NOT a covenant entrypoint: buildCreateV4 carries
 * a 3-field genesis accounting. The manifest's 11-field ledger is
 * synthesized from the frozen transaction and that genesis accounting —
 * every quantity a real builder value, no invented number. checkValue
 * conservation's genesis identity (fee = externalIn − successorTotal −
 * externalOut) then re-proves it.
 */
function genesisAccounting(build, txDoc, effects) {
  const acc = build.accounting;
  if (!isPlainObject(acc)) refuse("BRIDGE_BUILD_INVALID", "a genesis build must carry accounting");
  let externalIn = 0n;
  txDoc.inputs.forEach((input, i) => {
    if (effects.inputs[i] === "external") externalIn += toBigIntStrict(String(input.utxo.amount), `input[${i}].utxo.amount`);
  });
  let externalOut = 0n;
  txDoc.outputs.forEach((output, i) => {
    const kind = effects.outputs[i];
    if (kind === "change" || kind === "agentFuel") externalOut += toBigIntStrict(String(output.value), `output[${i}].value`);
  });
  const successorTotal = toBigIntStrict(String(acc.vaultValue), "build.accounting.vaultValue");
  const fee = externalIn - successorTotal - externalOut;
  if (fee < 0n) refuse("BRIDGE_BUILD_INVALID", "genesis funding does not cover the vault value plus change");
  return {
    predecessorProtected: "0",
    predecessorFeeReserve: "0",
    payAmount: "0",
    reserveConsumed: "0",
    externalIn: externalIn.toString(),
    externalOut: externalOut.toString(),
    fee: fee.toString(),
    successorProtected: String(acc.protectedValue),
    successorFeeReserve: String(acc.feeReserve),
    successorTotal: successorTotal.toString(),
    terminalPayout: "0"
  };
}

/* ------------------------------------------------------------------ */
/* requested-intent reconstruction                                     */
/* ------------------------------------------------------------------ */

/*
 * The canonical requested-intent document this build REALIZES. In
 * production the requested intent originates from the user's/agent's
 * request and the bridge BINDS the request to the build; deriveRequestedIntent
 * reconstructs the resolved intent from the builder's realized facts (the
 * resolved newAgentRoot, the exact top-up delta, the exact payment) so a
 * caller can obtain, verify against, or diff the intent the build satisfies.
 * Only sdkActions are produced (buildV4Transaction operates at the sdkAction
 * layer; high-level lifecycle actions resolve to ownerSetAgentRoot upstream
 * of the builder — sdk/src/wallet-requests-v4.js planV4).
 */
function deriveRequestedIntent(build, { maxFeeSompi = null } = {}) {
  requireField(build, "networkId", "build.networkId");
  const covenantVersion = requireField(build, "contractVersion", "build.contractVersion");
  const template = requireField(build, "template", "build.template");
  const base = {
    intentVersion: "policyvault-requested-intent/1",
    networkId: build.networkId,
    vaultId: requireField(template, "vaultId", "build.template.vaultId"),
    covenantVersion,
    maxFeeSompi
  };

  if (build.kind === "genesis") {
    const fuel = genesisFuelFromBuild(build);
    return { ...base, action: "createVault", params: { owner: template.owner, initialState: build.initialState, agentFuel: fuel } };
  }

  const action = build.action;
  switch (action) {
    case "agentSpend": {
      const ce = requireField(build, "callExtra", "build.callExtra");
      const pay = requireField(build, "payment", "build.payment");
      return {
        ...base,
        action,
        params: {
          agentPk: ce.agentPk,
          recipient: pay.recipient,
          payAmountSompi: String(pay.value),
          periodsElapsed: String(ce.periodsElapsed),
          reserveConsumedSompi: String(build.accounting.reserveConsumed)
        }
      };
    }
    case "ownerSetAgentRoot":
      return { ...base, action, params: { newAgentRoot: build.successorState.agentRoot } };
    case "ownerSetApprovers":
      return {
        ...base,
        action,
        params: { newApproverSlots: [...build.successorState.approverSlots], newApprovalM: String(build.successorState.approvalM) }
      };
    case "ownerTopUp": {
      const delta = toBigIntStrict(String(build.successorState.protectedValue), "successor.protectedValue") - toBigIntStrict(String(build.stateJson.protectedValue), "predecessor.protectedValue");
      return { ...base, action, params: { topUpAmountSompi: delta.toString() } };
    }
    case "ownerTopUpReserve": {
      const delta = toBigIntStrict(String(build.successorState.feeReserve), "successor.feeReserve") - toBigIntStrict(String(build.stateJson.feeReserve), "predecessor.feeReserve");
      return { ...base, action, params: { topUpReserveAmountSompi: delta.toString() } };
    }
    case "ownerPause":
    case "ownerUnpause":
    case "ownerRecover":
      return { ...base, action, params: {} };
    default:
      refuse("BRIDGE_UNKNOWN_ACTION", `cannot reconstruct a requested intent for action ${JSON.stringify(action)} — failing closed`);
  }
}

/* The genesis agent-fuel output (if any), from the classified effects. */
function genesisFuelFromBuild(build) {
  const txDoc = transactionDoc(build);
  const effects = classifyEffects(build, txDoc);
  const idx = effects.outputs.indexOf("agentFuel");
  if (idx < 0) return null;
  const out = txDoc.outputs[idx];
  /* recover the x-only key from the P2PK script "20<x>ac". */
  const scriptHex = out.scriptPublicKey.scriptHex;
  if (typeof scriptHex !== "string" || !/^20[0-9a-f]{64}ac$/.test(scriptHex)) {
    refuse("BRIDGE_BUILD_INVALID", "genesis agent-fuel output is not a standard P2PK script");
  }
  return { xOnly: scriptHex.slice(2, 66), amountSompi: String(out.value) };
}

/* ------------------------------------------------------------------ */
/* the bridge                                                          */
/* ------------------------------------------------------------------ */

/*
 * Map a REAL builder output + a requested intent into buildIntentManifest
 * inputs. `build` is the frozen object returned by buildV4Transaction
 * (kind:"transition") or buildCreateV4 (kind:"genesis"). `requestedIntent`
 * is the caller's request document (omit to reconstruct it from the build
 * via deriveRequestedIntent — the resolved intent the build realizes).
 */
function deriveBuildInputs({ build, requestedIntent, maxFeeSompi = null } = {}) {
  if (!isPlainObject(build)) refuse("BRIDGE_BUILD_INVALID", "build must be the object returned by a v0.4 builder");
  const kind = build.kind;
  if (kind !== "transition" && kind !== "genesis") {
    refuse("BRIDGE_BUILD_INVALID", `unknown build.kind ${JSON.stringify(kind)} — failing closed (expected "transition" or "genesis")`);
  }
  const covenantVersion = requireField(build, "contractVersion", "build.contractVersion");
  if (!SUPPORTED_BUILD_VERSIONS.includes(covenantVersion)) {
    refuse("BRIDGE_UNSUPPORTED_VERSION", `build.contractVersion ${JSON.stringify(covenantVersion)} is not a supported v0.4-family version — failing closed`);
  }
  const template = requireField(build, "template", "build.template");
  const covenantId = requireField(build, "covenantId", "build.covenantId");
  const intent = requestedIntent !== undefined ? requestedIntent : deriveRequestedIntent(build, { maxFeeSompi });

  const txDoc = transactionDoc(build);
  const effects = classifyEffects(build, txDoc);

  const network = { networkId: requireField(build, "networkId", "build.networkId") };
  const vault = { vaultId: template.vaultId, owner: template.owner, covenantVersion, covenantId };

  if (kind === "genesis") {
    return {
      requestedIntent: intent,
      network,
      vault,
      signerXOnly: template.owner,
      transaction: txDoc,
      effects,
      stateBefore: null,
      stateAfter: { stateId: requireField(build, "stateId", "build.stateId"), state: build.initialState },
      accounting: genesisAccounting(build, txDoc, effects),
      payment: null,
      allowlist: null,
      approvals: null,
      limits: null,
      warnings: [],
      unexpectedEffects: []
    };
  }

  /* transition */
  const action = build.action;
  const isSpend = action === "agentSpend";
  const terminal = action === "ownerRecover";
  const signerXOnly = isSpend ? requireField(build.callExtra, "agentPk", "build.callExtra.agentPk") : template.owner;

  const stateBefore = {
    outpoint: requireField(build, "predecessorOutpoint", "build.predecessorOutpoint"),
    stateId: requireField(build, "predecessorStateId", "build.predecessorStateId"),
    state: requireField(build, "stateJson", "build.stateJson")
  };
  const stateAfter = terminal
    ? null
    : { stateId: requireField(build, "successorStateId", "build.successorStateId"), state: requireField(build, "successorState", "build.successorState") };

  let payment = null;
  let allowlist = null;
  let approvals = null;
  let limits = null;
  if (isSpend) {
    const pay = requireField(build, "payment", "build.payment");
    const outputIndex = effects.outputs.indexOf("payment");
    if (outputIndex < 0) refuse("BRIDGE_BUILD_INVALID", "an agentSpend build must contain a payment output");
    payment = { recipientXOnly: pay.recipient, amountSompi: String(pay.value), outputIndex };

    const policyBefore = policyBeforeFromBuild(build);
    const policyAfter = policyAfterFromBuild(build, policyBefore);
    allowlist = { agentRecipientRoot: policyBefore.agentRecipientRoot, recipientAllowlisted: true, proofSupplied: true };
    approvals = {
      aboveThreshold: build.aboveThreshold === true,
      approvalThreshold: String(policyBefore.approvalThreshold),
      requiredM: String(build.stateJson.approvalM)
    };
    limits = { policyBefore, policyAfter, periodsElapsed: String(build.callExtra.periodsElapsed) };
  }

  return {
    requestedIntent: intent,
    network,
    vault,
    signerXOnly,
    transaction: txDoc,
    effects,
    stateBefore,
    stateAfter,
    accounting: transitionAccounting(build),
    payment,
    allowlist,
    approvals,
    limits,
    warnings: [],
    unexpectedEffects: []
  };
}

/* Derive a manifest from a real builder output (self-validates through the
 * full strict schema inside buildIntentManifest). */
function deriveManifestFromV4Build(args) {
  return buildIntentManifest(deriveBuildInputs(args));
}

/*
 * Derive AND verify: returns { manifest, verification }. `decodedTransaction`
 * (an independent decode of the frozen tx) and `requestedIntent` (the
 * caller's independent request copy) are bound to the manifest's embedded
 * copies when supplied — omit either to verify the self-contained manifest.
 */
function deriveAndVerify({ build, requestedIntent, decodedTransaction, maxFeeSompi } = {}) {
  const manifest = deriveManifestFromV4Build({ build, requestedIntent, maxFeeSompi });
  const verification = verifyIntentManifest({ manifest, requestedIntent, decodedTransaction });
  return { manifest, verification };
}

module.exports = {
  SUPPORTED_BUILD_VERSIONS,
  AGENT_POLICY_FIELDS,
  deriveRequestedIntent,
  deriveBuildInputs,
  deriveManifestFromV4Build,
  deriveAndVerify
};
