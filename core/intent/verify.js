"use strict";

/*
 * PolicyVault Transaction Intent Manifest v1 — fail-closed verification.
 *
 * verifyIntentManifest compares a manifest against the structured
 * REQUESTED INTENT and the structured DECODED TRANSACTION and runs the
 * complete detector catalogue. Every detector returns structured
 * failures; the overall verdict is VERIFIED_EXACT — and the verified
 * statement is emitted — ONLY when every detector passes. Anything
 * unknown, missing, ambiguous, or unexplained REFUSES.
 *
 * Detector catalogue (spec §7):
 *   manifest-valid            schema/version/action/hash (validateManifest)
 *   intent-binding            supplied intent ≡ embedded intent
 *   transaction-binding       supplied decoded tx ≡ embedded transaction
 *   tx-shape                  requested action ⇒ exact transaction shape
 *   predecessor               covenant input = the exact predecessor UTXO
 *   successor                 covenant output = the exact declared successor
 *   outputs-explained         every output's script+value justified
 *   value-conservation        exact sompi ledger identities
 *   fee                       positive fee, bounded by the requested cap
 *   request-equations         requested parameters = manifest values
 *   state-transition          per-action state equations, authorized fields
 *   nonce-rule                exact per-action policyNonce rule
 *   policy-mutations-declared declared diff = recomputed diff
 *   limits                    agent policy arithmetic (v0.4 covenant rules)
 *   authority                 no unexplained authority expansion
 *   unexpected-effects        recorded unexplained effects refuse
 *
 * The equations mirror sdk/src/vault-transitions-v4.js and
 * sdk/src/vault-builders-v4.js exactly. What this verifier deliberately
 * does NOT re-implement (delegated to the layers that already prove it
 * with real consensus code): consensus hashing (txId/sighash come from
 * rusty-kaspa via pv_tx_probe), Schnorr signature verification, Merkle
 * fold recomputation, covenant script compilation, and VM execution.
 * The manifest pins those layers' outputs; this verifier proves the
 * transaction's declared meaning is EXACTLY the requested meaning.
 */

const { canonicalJsonStringify } = require("./canonical");
const { ACTIONS, validateManifest, diffStates, p2pkScriptHex } = require("./manifest");

const VERIFIED_STATEMENT = "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.";

const VERDICTS = Object.freeze({
  VERIFIED_EXACT: "VERIFIED_EXACT",
  REFUSED: "REFUSED"
});

function failure(code, detail) {
  return { code, detail };
}

function canonicalEqualSafe(a, b) {
  try {
    return canonicalJsonStringify(a) === canonicalJsonStringify(b);
  } catch {
    return false; // not canonically serializable -> never equal, fail closed
  }
}

/* ------------------------------------------------------------------ */
/* per-action transaction shapes (mirrors vault-builders-v4.js)        */
/* ------------------------------------------------------------------ */

const OWNER_MUTATION_ACTIONS = Object.freeze([
  "ownerSetAgentRoot",
  "ownerSetApprovers",
  "ownerTopUp",
  "ownerTopUpReserve",
  "ownerPause",
  "ownerUnpause"
]);

function allowedShapes(sdkAction) {
  if (sdkAction === "agentSpend") {
    return {
      inputs: [["covenant"], ["covenant", "external"]],
      /* The REAL SDK builder (sdk/src/vault-builders-v4.js agentSpend)
       * emits outputs in the order [payment, successor(, change)] — the
       * P2PK payment is output 0 and the covenant-bound successor is output
       * 1 (VM-proven by tests/vm/tests/v4_sdk_integration.rs, and every
       * §E11 negative vector mutates outputs[0]=payment / outputs[1]=
       * successor). The shape table MUST mirror the builder exactly, or the
       * verifier rejects every real agent spend (fail closed on a valid
       * transaction). All value/recipient/successor detectors locate
       * outputs by classification, not position, so this order change
       * weakens nothing. */
      outputs: [["payment", "successor"], ["payment", "successor", "change"]],
      /* fee fuel present <=> change present (vault-builders-v4 agentSpend) */
      coupled: true
    };
  }
  if (OWNER_MUTATION_ACTIONS.includes(sdkAction)) {
    return { inputs: [["covenant", "external"]], outputs: [["successor", "change"]], coupled: false };
  }
  if (sdkAction === "ownerRecover") {
    return { inputs: [["covenant", "external"]], outputs: [["recoverPayout", "change"]], coupled: false };
  }
  if (sdkAction === "createVault") {
    return {
      inputs: null, // any count >= 1, all external
      outputs: [["genesisVault", "change"], ["genesisVault", "agentFuel", "change"]],
      coupled: false
    };
  }
  return null; // unreachable after validateManifest; treated as refusal
}

function sequenceMatches(sequence, patterns) {
  return patterns.some((p) => p.length === sequence.length && p.every((k, i) => k === sequence[i]));
}

/* ------------------------------------------------------------------ */
/* detectors — each takes the validated context, returns failures      */
/* ------------------------------------------------------------------ */

function checkTxShape(ctx) {
  const { sdkAction, effects } = ctx;
  const failures = [];
  const shapes = allowedShapes(sdkAction);
  if (!shapes) {
    failures.push(failure("ACTION_TX_SHAPE_MISMATCH", `no transaction shape is defined for ${sdkAction} — failing closed`));
    return failures;
  }
  if (shapes.inputs === null) {
    if (!effects.inputKinds.every((k) => k === "external")) {
      failures.push(failure("ACTION_TX_SHAPE_MISMATCH", "createVault must be funded only by ordinary external inputs (no covenant input at genesis)"));
    }
  } else if (!sequenceMatches(effects.inputKinds, shapes.inputs)) {
    failures.push(
      failure(
        "ACTION_TX_SHAPE_MISMATCH",
        `${sdkAction} requires inputs ${JSON.stringify(shapes.inputs)}; the transaction carries ${JSON.stringify(effects.inputKinds)}`
      )
    );
  }
  if (!sequenceMatches(effects.outputKinds, shapes.outputs)) {
    const maxLen = Math.max(...shapes.outputs.map((p) => p.length));
    const code = effects.outputKinds.length > maxLen ? "UNEXPECTED_OUTPUT" : "ACTION_TX_SHAPE_MISMATCH";
    failures.push(
      failure(code, `${sdkAction} permits outputs ${JSON.stringify(shapes.outputs)}; the transaction carries ${JSON.stringify(effects.outputKinds)}`)
    );
  }
  if (shapes.coupled) {
    const hasFuel = effects.inputKinds.includes("external");
    const hasChange = effects.outputKinds.includes("change");
    if (hasFuel !== hasChange) {
      failures.push(failure("ACTION_TX_SHAPE_MISMATCH", "agentSpend: a fee-fuel input requires a change output and vice versa"));
    }
  }
  return failures;
}

function checkPredecessor(ctx) {
  const { manifest, info, txView, effects, stateBefore, accounting } = ctx;
  const failures = [];
  if (info.genesis) {
    if (accounting.predecessorProtected !== 0n || accounting.predecessorFeeReserve !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "genesis accounting must declare zero predecessor value"));
    }
    return failures;
  }
  const covenantIndex = effects.inputKinds.indexOf("covenant");
  if (covenantIndex !== 0) {
    failures.push(failure("PREDECESSOR_MISMATCH", "the covenant predecessor must be input 0"));
    return failures;
  }
  const input = txView.inputs[0];
  const op = stateBefore ? ctx.manifest.stateBefore.outpoint : null;
  if (!op || input.previousOutpoint.transactionId !== op.transactionId || input.previousOutpoint.index !== op.index) {
    failures.push(failure("PREDECESSOR_MISMATCH", "input 0 does not spend the declared predecessor outpoint"));
  }
  if (input.utxo.covenantId !== manifest.vault.covenantId) {
    failures.push(failure("PREDECESSOR_MISMATCH", "input 0 covenantId differs from the vault covenantId"));
  }
  const predTotal = accounting.predecessorProtected + accounting.predecessorFeeReserve;
  if (input.utxo.amount !== predTotal) {
    failures.push(failure("PREDECESSOR_MISMATCH", "input 0 value differs from predecessor protectedValue + feeReserve"));
  }
  if (stateBefore && (accounting.predecessorProtected !== stateBefore.state.protectedValue || accounting.predecessorFeeReserve !== stateBefore.state.feeReserve)) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting predecessor values differ from stateBefore"));
  }
  return failures;
}

function checkSuccessor(ctx) {
  const { manifest, info, txView, effects, stateAfter, accounting } = ctx;
  const failures = [];
  if (info.terminal) {
    if (accounting.successorProtected !== 0n || accounting.successorFeeReserve !== 0n || accounting.successorTotal !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "terminal accounting must declare zero successor value"));
    }
    return failures;
  }
  const boundIndexes = effects.outputKinds
    .map((k, i) => (k === "successor" || k === "genesisVault" ? i : -1))
    .filter((i) => i >= 0);
  if (boundIndexes.length !== 1) {
    failures.push(failure("WRONG_SUCCESSOR", `exactly one covenant-bound output is required; found ${boundIndexes.length}`));
    return failures;
  }
  const index = boundIndexes[0];
  const output = txView.outputs[index];
  if (output.covenant.covenantId !== manifest.vault.covenantId) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output carries a different covenantId than the vault"));
  }
  if (output.covenant.authorizingInput !== 0) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output must be authorized by input 0"));
  }
  if (output.scriptVersion !== 0) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output must use script version 0"));
  }
  const declaredTotal = stateAfter.state.protectedValue + stateAfter.state.feeReserve;
  if (accounting.successorTotal !== declaredTotal) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.successorTotal differs from stateAfter protectedValue + feeReserve"));
  }
  if (accounting.successorProtected !== stateAfter.state.protectedValue || accounting.successorFeeReserve !== stateAfter.state.feeReserve) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting successor values differ from stateAfter"));
  }
  if (output.value !== declaredTotal) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output value differs from the declared successor protectedValue + feeReserve"));
  }
  const expected = stateAfter.expectedOutpoint;
  if (expected.transactionId !== txView.txId || expected.index !== index) {
    failures.push(failure("WRONG_SUCCESSOR", "stateAfter.expectedOutpoint does not name this transaction's covenant-bound output"));
  }
  return failures;
}

function checkOutputsExplained(ctx) {
  const { manifest, txView, effects, payment, accounting } = ctx;
  const failures = [];
  effects.outputKinds.forEach((kind, i) => {
    const output = txView.outputs[i];
    if (kind === "payment") {
      if (!payment) {
        failures.push(failure("UNEXPECTED_OUTPUT", `output ${i} is classified payment but the manifest declares no payment`));
        return;
      }
      if (payment.outputIndex !== i) {
        failures.push(failure("UNEXPECTED_OUTPUT", `manifest.payment.outputIndex ${payment.outputIndex} does not name output ${i}`));
      }
      if (output.value !== payment.amountSompi) {
        failures.push(failure("HIDDEN_RECIPIENT", `payment output ${i} value differs from the declared payment amount`));
      }
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(payment.recipientXOnly)) {
        failures.push(failure("HIDDEN_RECIPIENT", `payment output ${i} does not pay the declared recipient key`));
      }
    } else if (kind === "change") {
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(manifest.actor.signerXOnly)) {
        failures.push(failure("HIDDEN_RECIPIENT", `change output ${i} does not return to the signing wallet — value would leave through "change"`));
      }
    } else if (kind === "recoverPayout") {
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(manifest.vault.owner)) {
        failures.push(failure("HIDDEN_RECIPIENT", `recovery payout output ${i} does not pay the vault owner`));
      }
      if (output.value !== accounting.terminalPayout) {
        failures.push(failure("TERMINAL_PAYOUT_MISMATCH", `recovery payout output ${i} value differs from accounting.terminalPayout`));
      }
    } else if (kind === "agentFuel") {
      const fuel = manifest.requested.params.agentFuel ?? null;
      if (!fuel) {
        failures.push(failure("UNEXPECTED_OUTPUT", `output ${i} is classified agentFuel but the requested intent declares none`));
        return;
      }
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(fuel.xOnly)) {
        failures.push(failure("HIDDEN_RECIPIENT", `agent fuel output ${i} does not pay the requested agent key`));
      }
      if (output.value.toString() !== fuel.amountSompi) {
        failures.push(failure("REQUEST_MISMATCH", `agent fuel output ${i} value differs from the requested amount`));
      }
    }
    /* successor / genesisVault are fully checked by checkSuccessor. */
  });
  if (payment) {
    const kindAt = effects.outputKinds[payment.outputIndex];
    if (kindAt !== "payment") {
      failures.push(failure("HIDDEN_RECIPIENT", `manifest.payment.outputIndex ${payment.outputIndex} is classified ${kindAt}, not payment`));
    }
  }
  return failures;
}

function checkValueConservation(ctx) {
  const { info, sdkAction, txView, effects, accounting } = ctx;
  const failures = [];
  const totalIn = txView.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = txView.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== accounting.fee) {
    failures.push(
      failure("VALUE_CONSERVATION_VIOLATION", `inputs (${totalIn}) − outputs (${totalOut}) = ${totalIn - totalOut} sompi, but accounting.fee declares ${accounting.fee}`)
    );
  }
  let externalIn = 0n;
  txView.inputs.forEach((input, i) => {
    if (effects.inputKinds[i] === "external") externalIn += input.utxo.amount;
  });
  if (externalIn !== accounting.externalIn) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.externalIn differs from the sum of external input values"));
  }
  let externalOut = 0n;
  let paymentOut = 0n;
  let payoutOut = 0n;
  txView.outputs.forEach((output, i) => {
    const kind = effects.outputKinds[i];
    if (kind === "change" || kind === "agentFuel") externalOut += output.value;
    if (kind === "payment") paymentOut += output.value;
    if (kind === "recoverPayout") payoutOut += output.value;
  });
  if (externalOut !== accounting.externalOut) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.externalOut differs from the sum of change/agent-fuel output values"));
  }
  if (paymentOut !== accounting.payAmount) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.payAmount differs from the payment output value"));
  }
  if (info.terminal) {
    if (payoutOut !== accounting.terminalPayout) {
      failures.push(failure("ACCOUNTING_MISMATCH", "accounting.terminalPayout differs from the recovery payout output value"));
    }
    const predTotal = accounting.predecessorProtected + accounting.predecessorFeeReserve;
    if (accounting.terminalPayout !== predTotal) {
      failures.push(failure("TERMINAL_PAYOUT_MISMATCH", "the covenant requires the terminal payout to equal protectedValue + feeReserve exactly"));
    }
    if (accounting.reserveConsumed !== 0n || accounting.payAmount !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "terminal accounting must declare zero payAmount and reserveConsumed"));
    }
    if (accounting.fee !== accounting.externalIn - accounting.externalOut) {
      failures.push(failure("VALUE_CONSERVATION_VIOLATION", "terminal fee must equal external fuel in minus change out"));
    }
  } else if (info.genesis) {
    if (accounting.reserveConsumed !== 0n || accounting.payAmount !== 0n || accounting.terminalPayout !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "genesis accounting must declare zero payAmount, reserveConsumed, and terminalPayout"));
    }
    if (accounting.fee !== accounting.externalIn - accounting.successorTotal - accounting.externalOut) {
      failures.push(failure("VALUE_CONSERVATION_VIOLATION", "genesis fee must equal funding in minus vault value minus change out"));
    }
  } else {
    if (accounting.terminalPayout !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "a non-terminal transition must declare terminalPayout 0"));
    }
    if (sdkAction !== "agentSpend" && (accounting.payAmount !== 0n || accounting.reserveConsumed !== 0n)) {
      failures.push(failure("ACCOUNTING_MISMATCH", `${sdkAction} must declare zero payAmount and reserveConsumed`));
    }
    /* General non-terminal ledger identity: what left the covenant
     * (predTotal − succTotal, negative for top-ups) minus the payment,
     * plus the net external fuel contribution, is exactly the fee. */
    const predTotal = accounting.predecessorProtected + accounting.predecessorFeeReserve;
    if (accounting.fee !== predTotal - accounting.successorTotal - accounting.payAmount + accounting.externalIn - accounting.externalOut) {
      failures.push(
        failure("VALUE_CONSERVATION_VIOLATION", "fee must equal (predecessor total − successor total) − payAmount + externalIn − externalOut exactly")
      );
    }
    /* agentSpend: the covenant drawdown decomposes exactly into the
     * payment plus the reserve-funded fee portion — nothing else. */
    if (sdkAction === "agentSpend" && predTotal - accounting.successorTotal !== accounting.payAmount + accounting.reserveConsumed) {
      failures.push(failure("VALUE_CONSERVATION_VIOLATION", "an agent spend must draw down the covenant by exactly payAmount + reserveConsumed"));
    }
  }
  return failures;
}

function checkFee(ctx) {
  const { manifest, accounting } = ctx;
  const failures = [];
  if (accounting.fee < 1n) {
    failures.push(failure("VALUE_CONSERVATION_VIOLATION", "a real transaction pays a positive network fee"));
  }
  const maxFee = manifest.requested.maxFeeSompi;
  if (maxFee !== null && accounting.fee > BigInt(maxFee)) {
    failures.push(failure("EXCESSIVE_FEE", `accounting.fee ${accounting.fee} exceeds the requested maxFeeSompi ${maxFee}`));
  }
  return failures;
}

function checkRequestEquations(ctx) {
  const { manifest, sdkAction, stateBefore, stateAfter, accounting, payment, limits } = ctx;
  const failures = [];
  const params = manifest.requested.params;
  const miss = (detail) => failures.push(failure("REQUEST_MISMATCH", detail));
  switch (sdkAction) {
    case "agentSpend": {
      if (manifest.actor.agentPk !== params.agentPk) miss("the acting agent differs from the requested agentPk");
      if (payment.recipientXOnly !== params.recipient) miss("the payment recipient differs from the requested recipient");
      if (payment.amountSompi.toString() !== params.payAmountSompi) miss("the payment amount differs from the requested payAmountSompi");
      if (limits.periodsElapsed.toString() !== params.periodsElapsed) miss("limits.periodsElapsed differs from the requested periodsElapsed");
      if (accounting.reserveConsumed.toString() !== params.reserveConsumedSompi) miss("accounting.reserveConsumed differs from the requested reserveConsumedSompi");
      break;
    }
    case "ownerSetAgentRoot": {
      if (stateAfter.state.agentRoot !== params.newAgentRoot) miss("the successor agentRoot differs from the requested newAgentRoot");
      break;
    }
    case "ownerSetApprovers": {
      if (!canonicalEqualSafe(manifest.stateAfter.state.approverSlots, params.newApproverSlots)) {
        miss("the successor approver slots differ from the requested newApproverSlots");
      }
      if (stateAfter.state.approvalM.toString() !== params.newApprovalM) miss("the successor approvalM differs from the requested newApprovalM");
      break;
    }
    case "ownerTopUp": {
      const delta = stateAfter.state.protectedValue - stateBefore.state.protectedValue;
      if (delta.toString() !== params.topUpAmountSompi) miss("the protectedValue increase differs from the requested topUpAmountSompi");
      break;
    }
    case "ownerTopUpReserve": {
      const delta = stateAfter.state.feeReserve - stateBefore.state.feeReserve;
      if (delta.toString() !== params.topUpReserveAmountSompi) miss("the feeReserve increase differs from the requested topUpReserveAmountSompi");
      break;
    }
    case "ownerPause":
    case "ownerUnpause":
    case "ownerRecover":
      break; // parameterless; the transition itself is the request
    case "createVault": {
      if (manifest.vault.owner !== params.owner) miss("the vault owner differs from the requested owner");
      if (!canonicalEqualSafe(manifest.stateAfter.state, params.initialState)) {
        miss("the genesis state differs from the requested initialState");
      }
      break;
    }
    default:
      failures.push(failure("UNKNOWN_ACTION", `no request equations for ${sdkAction} — failing closed`));
  }
  return failures;
}

function checkStateTransition(ctx) {
  const { manifest, sdkAction, info, stateBefore, stateAfter, accounting } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures;
  const before = stateBefore.state;
  const after = stateAfter.state;

  /* Frozen per-entrypoint field-preservation matrix: any field outside the
   * action's authorized-change set MUST be preserved (policyNonce has its
   * own detector). A violation is a hidden policy mutation. */
  const preserved = {
    protectedValue: before.protectedValue === after.protectedValue,
    feeReserve: before.feeReserve === after.feeReserve,
    paused: before.paused === after.paused,
    agentRoot: before.agentRoot === after.agentRoot,
    approverSlots: canonicalEqualSafe(manifest.stateBefore.state.approverSlots, manifest.stateAfter.state.approverSlots),
    approvalM: before.approvalM === after.approvalM
  };
  for (const [field, same] of Object.entries(preserved)) {
    if (!same && !info.mutable.includes(field)) {
      failures.push(failure("HIDDEN_POLICY_MUTATION", `${sdkAction} is not authorized to change ${field}, but the successor state changes it`));
    }
  }

  switch (sdkAction) {
    case "agentSpend": {
      if (before.paused !== 0n) failures.push(failure("STATE_MISMATCH", "agentSpend requires an unpaused predecessor"));
      if (after.protectedValue !== before.protectedValue - accounting.payAmount) {
        failures.push(failure("STATE_MISMATCH", "successor protectedValue must decrease by exactly the payment amount"));
      }
      if (after.feeReserve !== before.feeReserve - accounting.reserveConsumed) {
        failures.push(failure("STATE_MISMATCH", "successor feeReserve must decrease by exactly reserveConsumed"));
      }
      if (after.agentRoot === before.agentRoot) {
        failures.push(failure("STATE_MISMATCH", "an agent spend always advances the agent's period accounting — the successor agentRoot cannot equal the predecessor root"));
      }
      break;
    }
    case "ownerTopUp": {
      if (after.protectedValue <= before.protectedValue) {
        failures.push(failure("STATE_MISMATCH", "ownerTopUp must strictly increase protectedValue"));
      }
      break;
    }
    case "ownerTopUpReserve": {
      if (after.feeReserve <= before.feeReserve) {
        failures.push(failure("STATE_MISMATCH", "ownerTopUpReserve must strictly increase feeReserve"));
      }
      break;
    }
    case "ownerPause": {
      if (before.paused !== 0n || after.paused !== 1n) {
        failures.push(failure("STATE_MISMATCH", "ownerPause must transition paused 0 -> 1"));
      }
      break;
    }
    case "ownerUnpause": {
      if (before.paused !== 1n || after.paused !== 0n) {
        failures.push(failure("STATE_MISMATCH", "ownerUnpause must transition paused 1 -> 0"));
      }
      break;
    }
    case "ownerSetApprovers": {
      if (after.activeCount < 1 || after.approvalM < 1n) {
        failures.push(failure("STATE_MISMATCH", "the covenant cannot transition to a zero-approver configuration (ownerSetApprovers requires 1 <= approvalM <= activeCount)"));
      }
      break;
    }
    case "ownerSetAgentRoot":
      break; // the root equality with the request is checked in request-equations
    default:
      failures.push(failure("UNKNOWN_ACTION", `no state-transition equations for ${sdkAction} — failing closed`));
  }
  return failures;
}

function checkNonceRule(ctx) {
  const { info, stateBefore, stateAfter } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures;
  const before = stateBefore.state.policyNonce;
  const after = stateAfter.state.policyNonce;
  const expected = info.nonce === "increment" ? before + 1n : before;
  if (after !== expected) {
    failures.push(
      failure(
        "NONCE_RULE_VIOLATION",
        `policyNonce must be ${info.nonce === "increment" ? "incremented by exactly 1" : "preserved"} (expected ${expected}, successor declares ${after})`
      )
    );
  }
  return failures;
}

function checkPolicyMutationsDeclared(ctx) {
  const { manifest, info } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures; // schema enforces []
  const recomputed = diffStates(manifest.stateBefore.state, manifest.stateAfter.state);
  if (!canonicalEqualSafe(recomputed, manifest.policyMutations)) {
    failures.push(
      failure("POLICY_MUTATION_MISDECLARED", "manifest.policyMutations does not equal the recomputed stateBefore→stateAfter diff — declared and actual mutations diverge")
    );
  }
  return failures;
}

function checkLimits(ctx) {
  const { manifest, sdkAction, txView, stateBefore, accounting, payment, allowlist, approvals, limits } = ctx;
  const failures = [];
  if (sdkAction !== "agentSpend") return failures;
  const pb = limits.policyBefore;
  const pa = limits.policyAfter;
  const pay = payment.amountSompi;

  if (pb.agentPk !== manifest.actor.agentPk) {
    failures.push(failure("AGENT_POLICY_MISMATCH", "limits.policyBefore.agentPk differs from the acting agent"));
  }
  if (pa.agentPk !== pb.agentPk) {
    failures.push(failure("AGENT_POLICY_MISMATCH", "an agent spend never changes the agent key"));
  }
  if (pay > pb.maxPerSpend) {
    failures.push(failure("LIMIT_VIOLATION", "payAmount exceeds this agent's maxPerSpend"));
  }

  /* Exact covenant rollover arithmetic (vault-transitions-v4 agentSpend). */
  const periods = limits.periodsElapsed;
  let newStart = pb.periodStartDaa;
  let newSpent = pb.periodSpent + pay;
  let requiredLockTime = 0n;
  if (periods >= 1n) {
    newStart = pb.periodStartDaa + periods * pb.periodLengthDaa;
    newSpent = pay;
    requiredLockTime = newStart; // covenant CLTV: lockTime >= newStart; the builder pins equality
  }
  if (newSpent > pb.periodBudget) {
    failures.push(failure("LIMIT_VIOLATION", "the spend exceeds this agent's remaining period budget"));
  }
  if (txView.lockTime !== requiredLockTime) {
    failures.push(failure("LOCKTIME_RULE_VIOLATION", `transaction lockTime must be ${requiredLockTime} for periodsElapsed ${periods}`));
  }
  const expectedAfter = { ...pb, periodStartDaa: newStart, periodSpent: newSpent };
  for (const field of Object.keys(expectedAfter)) {
    if (pa[field] !== expectedAfter[field]) {
      failures.push(failure("AGENT_POLICY_MISMATCH", `limits.policyAfter.${field} does not follow the covenant's single-leaf update arithmetic`));
    }
  }

  if (accounting.reserveConsumed > pb.agentMaxFeePerTx) {
    failures.push(failure("RESERVE_RULE_VIOLATION", "reserveConsumed exceeds this agent's agentMaxFeePerTx"));
  }
  if (accounting.reserveConsumed > accounting.predecessorFeeReserve) {
    failures.push(failure("RESERVE_RULE_VIOLATION", "reserveConsumed exceeds the available fee reserve"));
  }

  const shouldBeAbove = pay > pb.approvalThreshold;
  if (approvals.aboveThreshold !== shouldBeAbove) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", `payAmount ${pay} vs approvalThreshold ${pb.approvalThreshold}: aboveThreshold must be ${shouldBeAbove}`));
  }
  if (approvals.approvalThreshold !== pb.approvalThreshold) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", "approvals.approvalThreshold differs from the agent policy's approvalThreshold"));
  }
  if (approvals.requiredM !== stateBefore.state.approvalM) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", "approvals.requiredM differs from the vault's approvalM"));
  }
  if (shouldBeAbove && stateBefore.state.approvalM < 1n) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", "an above-threshold spend requires an approver configuration (approvalM >= 1)"));
  }

  if (allowlist.agentRecipientRoot !== pb.agentRecipientRoot) {
    failures.push(failure("ALLOWLIST_MISMATCH", "allowlist.agentRecipientRoot differs from the agent policy's agentRecipientRoot"));
  }
  if (allowlist.recipientAllowlisted !== true || allowlist.proofSupplied !== true) {
    failures.push(failure("ALLOWLIST_NOT_PROVEN", "the recipient's allowlist membership is not recorded as proven — refusing"));
  }
  return failures;
}

function checkAuthority(ctx) {
  const { manifest, sdkAction, info, stateBefore, stateAfter } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures;
  const before = stateBefore.state;
  const after = stateAfter.state;
  const expand = (detail) => failures.push(failure("AUTHORITY_EXPANSION", detail));

  const approversChanged =
    before.approvalM !== after.approvalM ||
    !canonicalEqualSafe(manifest.stateBefore.state.approverSlots, manifest.stateAfter.state.approverSlots);
  if (approversChanged && sdkAction !== "ownerSetApprovers") {
    expand(`${sdkAction} changes the approval configuration — only ownerSetApprovers may`);
  }
  if (after.agentRoot !== before.agentRoot && sdkAction !== "agentSpend" && sdkAction !== "ownerSetAgentRoot") {
    expand(`${sdkAction} changes the agent registry root — only agentSpend (single-leaf accounting) or ownerSetAgentRoot may`);
  }
  if (before.paused === 1n && after.paused === 0n && sdkAction !== "ownerUnpause") {
    expand(`${sdkAction} silently unpauses the vault — only ownerUnpause may`);
  }
  if (after.policyNonce > before.policyNonce && info.nonce !== "increment") {
    expand(`${sdkAction} advances the policyNonce without being a policy-mutation entrypoint`);
  }
  if (after.protectedValue < before.protectedValue && sdkAction !== "agentSpend") {
    expand(`${sdkAction} moves protected value out of the vault — only agentSpend may`);
  }
  if (after.feeReserve < before.feeReserve && sdkAction !== "agentSpend") {
    expand(`${sdkAction} consumes the fee reserve — only agentSpend may`);
  }
  return failures;
}

function checkUnexpectedEffects(ctx) {
  const list = ctx.manifest.unexpectedEffects;
  if (list.length === 0) return [];
  return list.map((e) => failure("UNEXPECTED_EFFECTS_PRESENT", `recorded unexplained effect ${e.code}: ${e.detail}`));
}

/* ------------------------------------------------------------------ */
/* the verifier                                                        */
/* ------------------------------------------------------------------ */

const DETECTORS = Object.freeze([
  ["tx-shape", checkTxShape],
  ["predecessor", checkPredecessor],
  ["successor", checkSuccessor],
  ["outputs-explained", checkOutputsExplained],
  ["value-conservation", checkValueConservation],
  ["fee", checkFee],
  ["request-equations", checkRequestEquations],
  ["state-transition", checkStateTransition],
  ["nonce-rule", checkNonceRule],
  ["policy-mutations-declared", checkPolicyMutationsDeclared],
  ["limits", checkLimits],
  ["authority", checkAuthority],
  ["unexpected-effects", checkUnexpectedEffects]
]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function refusedResult(checks, failures, manifestHash) {
  return deepFreeze({
    ok: false,
    verdict: VERDICTS.REFUSED,
    statement: null,
    manifestHash: manifestHash ?? null,
    txId: null,
    checks,
    failures
  });
}

/*
 * Verify a manifest against the structured requested intent and the
 * structured decoded transaction.
 *
 *   verifyIntentManifest({ manifest, requestedIntent, decodedTransaction })
 *
 * `requestedIntent` and `decodedTransaction` are the caller's independent
 * copies (from the user/agent request and from an independent decode of
 * the frozen transaction). When supplied they must be canonically
 * IDENTICAL to the manifest's embedded copies; omit a side (undefined) to
 * verify a self-contained manifest against its own embedded copies.
 *
 * Returns a structured, deep-frozen result:
 *   { ok, verdict, statement, manifestHash, txId, checks, failures }
 * ok=true and verdict=VERIFIED_EXACT ONLY when every detector passed —
 * then, and only then, `statement` carries the verified claim. Any
 * failure — including an internal verifier error — refuses.
 */
function verifyIntentManifest({ manifest, requestedIntent, decodedTransaction } = {}) {
  const checks = [];
  const allFailures = [];

  /* 1. Strict validation (schema, versions, actions, hash). A manifest
   * that fails validation is hard-refused immediately: no later detector
   * may run over an untrusted structure. */
  let ctx;
  try {
    ctx = validateManifest(manifest);
  } catch (e) {
    const f = failure(e.code ?? "SCHEMA_INVALID", e.message);
    checks.push({ id: "manifest-valid", ok: false, failures: [f] });
    return refusedResult(checks, [f], null);
  }
  checks.push({ id: "manifest-valid", ok: true, failures: [] });

  /* 2. Binding to the caller's independent copies. */
  if (requestedIntent !== undefined) {
    const ok = canonicalEqualSafe(requestedIntent, ctx.manifest.requested);
    const f = ok ? [] : [failure("REQUEST_MISMATCH", "the supplied requested intent differs from the manifest's embedded intent")];
    checks.push({ id: "intent-binding", ok, failures: f });
    allFailures.push(...f);
  }
  if (decodedTransaction !== undefined) {
    const ok = canonicalEqualSafe(decodedTransaction, ctx.manifest.transaction);
    const f = ok ? [] : [failure("TX_MISMATCH", "the supplied decoded transaction differs from the manifest's embedded transaction — the manifest does not describe this transaction")];
    checks.push({ id: "transaction-binding", ok, failures: f });
    allFailures.push(...f);
  }

  /* 3. The detector catalogue. An unexpected internal error in any
   * detector REFUSES (fail closed) — it never skips. */
  for (const [id, detector] of DETECTORS) {
    let failuresHere;
    try {
      failuresHere = detector(ctx);
    } catch (e) {
      failuresHere = [failure("VERIFIER_INTERNAL", `${id}: ${e.message} — failing closed`)];
    }
    checks.push({ id, ok: failuresHere.length === 0, failures: failuresHere });
    allFailures.push(...failuresHere);
  }

  const ok = allFailures.length === 0;
  return deepFreeze({
    ok,
    verdict: ok ? VERDICTS.VERIFIED_EXACT : VERDICTS.REFUSED,
    statement: ok ? VERIFIED_STATEMENT : null,
    manifestHash: ctx.manifest.manifestHash,
    txId: ctx.manifest.transaction.txId,
    checks,
    failures: allFailures
  });
}

module.exports = {
  VERIFIED_STATEMENT,
  VERDICTS,
  ACTIONS,
  verifyIntentManifest
};
