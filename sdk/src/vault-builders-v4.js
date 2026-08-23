"use strict";

/*
 * PolicyVault v0.4 OFFLINE transaction builders (Checkpoint E §E4/§E6/§E9).
 *
 * Deterministic, fully-offline construction of the genesis transaction and
 * all 8 production covenant entrypoints:
 *
 *   agentSpend, ownerSetAgentRoot, ownerSetApprovers, ownerTopUp,
 *   ownerTopUpReserve, ownerPause, ownerUnpause, ownerRecover
 *
 * Pipeline discipline (builders NEVER broadcast; no network access here):
 *
 *   1. normalize the predecessor (strict; recovery-parse ONLY for
 *      ownerRecover);
 *   2. resolve the agent policy + proof and recipient proof from the
 *      caller's canonical trees (or verify supplied proofs) — a proof
 *      that does not match the live state cannot build;
 *   3. derive the single canonical successor (vault-transitions-v4) —
 *      callers never supply successor fields;
 *   4. compile the exact predecessor/successor states (silverc);
 *   5. select the proven-safe compute budget (compute-budget-v4);
 *   6. compute the EXACT fee from the final shape: the covenant call is
 *      encoded through the REAL pv_call_encoder with fixed-width
 *      placeholder signatures (65-byte sig, 650-byte approvals blob), so
 *      the sig-script length at fee time equals the final length exactly;
 *   7. FREEZE the transaction (frozen-tx-v3, version-agnostic) — txId +
 *      covenant sighash from real consensus code;
 *   8. (above the agent's threshold) create the approval package and
 *      collect approvals against the frozen transaction;
 *   9. finalize: encode the real covenant call through the SAME
 *      production encoder and assemble the exact final signature
 *      scripts. Finalize ASSERTS the call length matches the fee-time
 *      length (FEE_DRIFT fails closed) and never touches a frozen field.
 *
 * FEE-RESERVE ACCOUNTING (§E4 — the v0.4 conservation theorem):
 *   fee = reserveConsumed + (externalIn − externalOut), and the covenant
 *   requires reserveConsumed <= min(leaf.agentMaxFeePerTx, fee), so
 *   externalOut <= externalIn: covenant value never escapes to a
 *   non-pinned output. Two agent-spend funding modes:
 *     RESERVE mode (no chain.fuel): the exact network fee is consumed
 *       from the covenant fee reserve (reserveConsumed == fee, derived by
 *       a bounded fixed-point over the successor encoding — the encoded
 *       call length can shift by a byte when feeReserve crosses a
 *       script-number width boundary);
 *     FUEL mode (chain.fuel present): the caller chooses reserveConsumed
 *       (default 0) within [0, min(cap, reserve, fee)]; the ordinary fuel
 *       input pays the remainder and receives change.
 *   Protected principal moves ONLY by the exact payment / top-up /
 *   recovery amount — never as fee. Insufficient reserve/fuel fails with
 *   a specific code rather than mutating any other policy dimension.
 *   Owner recovery requires ordinary fuel (output 0 is pinned to the FULL
 *   protected + reserve payout) and therefore works with an EMPTY reserve.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const {
  CONTRACT_VERSION_V4,
  CONTRACT_VERSION_V4_1,
  OWNER_OP_SELECTOR_V4_1,
  resolveV4Abi,
  MAX_APPROVERS,
  normalizeTemplateV4,
  normalizeStateV4,
  normalizeStateV4ForRecovery,
  computeStateIdV4,
  stateToJsonV4
} = require("./vault-state-v4");

/*
 * Encoder call shape for an sdkAction under a resolved ABI. v0.4 names each
 * owner op directly; v0.4.1 routes the six owner ops through ONE ownerControl
 * entrypoint selected by an opSelector call arg. agentSpend and ownerRecover
 * keep their names in both versions.
 */
function encoderFunctionShape(abi, action) {
  if (abi.consolidatedOwner && OWNER_OP_SELECTOR_V4_1[action] !== undefined) {
    return { function: "ownerControl", extra: { opSelector: OWNER_OP_SELECTOR_V4_1[action] } };
  }
  return { function: action, extra: {} };
}
const { compileExactStateV4 } = require("./contract-compiler-v4");
const {
  agentSpendSuccessorV4,
  setAgentRootSuccessorV4,
  setApproversSuccessorV4,
  topUpSuccessorV4,
  topUpReserveSuccessorV4,
  pauseSuccessorV4,
  recoverPlanV4
} = require("./vault-transitions-v4");
const { selectComputeBudgetV4, V4_BUDGET } = require("./compute-budget-v4");
const { buildAgentTreeV4, generateAgentProofV4, verifyAgentProofV4 } = require("./agent-merkle-v4");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { covenantSigscript } = require("./spend-vault");
const {
  createApprovalPackageV4,
  placeholderApprovalsBlob,
  approvalsBlobV4,
  p2pkScriptHex
} = require("./approval-package-v4");

const ENCODER_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder");
const PLACEHOLDER_SIG_HEX = "00".repeat(65);
const ORDINARY_SIGSCRIPT_LEN = 66; // 0x41 push + 65-byte Schnorr signature
/* The production covenant's fee introspection bound (txFee():
 * require(inCount <= 8) / require(outCount <= 8)) — agent spends beyond
 * this shape are consensus-invalid. */
const MAX_TX_FEE_IO = 8;

const OWNER_ACTIONS = new Set([
  "ownerSetAgentRoot",
  "ownerSetApprovers",
  "ownerTopUp",
  "ownerTopUpReserve",
  "ownerPause",
  "ownerUnpause",
  "ownerRecover"
]);
const SPEND_ACTIONS = new Set(["agentSpend"]);

function fail(message, code) {
  const error = new Error(`vault-builders-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

/*
 * Recursively freeze a plain-object/array tree (Checkpoint F §F10 hardening).
 * The build object is Object.freeze'd shallowly, which leaves nested
 * callExtra/accounting/proof objects mutable by reference. finalize trusts
 * build.callExtra, so — even though any resulting mismatch is caught by the
 * covenant (output/leaf binding), never moving funds — deep-freeze removes
 * the aliasing surface entirely. Strings/BigInt/number leaves are already
 * immutable; this only walks objects and arrays.
 */
function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) {
      deepFreeze(value[key]);
    }
  }
  return value;
}

function runEncoderV4({ sourcePath, constructorArgsPath, call, contractVersion = CONTRACT_VERSION_V4 }) {
  if (!fs.existsSync(ENCODER_PATH)) {
    fail(`pv_call_encoder not built: ${ENCODER_PATH}`);
  }
  const callPath = path.join(os.tmpdir(), `pv4-call-${process.pid}-${crypto.randomUUID()}.json`);
  // contractVersion is injected last so it is authoritative and cannot be
  // spoofed by a stray field in `call`.
  fs.writeFileSync(callPath, JSON.stringify({ ...call, contractVersion }), { mode: 0o600 });
  try {
    const result = spawnSync(ENCODER_PATH, [sourcePath, constructorArgsPath, callPath], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024
    });
    if (result.status !== 0) {
      fail(`covenant call encoding failed: ${result.stderr?.trim() ?? result.status}`);
    }
    const hex = result.stdout.trim();
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
      fail("pv_call_encoder returned invalid hex");
    }
    return hex;
  } finally {
    fs.unlinkSync(callPath);
  }
}

/* The v0.4 successor object in the encoder's call.json field names. */
function successorCallJsonV4(stateJson) {
  const successor = {
    protectedValue: stateJson.protectedValue,
    feeReserve: stateJson.feeReserve,
    paused: Number(stateJson.paused),
    agentRoot: stateJson.agentRoot,
    approvalM: stateJson.approvalM,
    policyNonce: stateJson.policyNonce
  };
  stateJson.approverSlots.forEach((key, i) => {
    successor[`approver${i + 1}`] = key;
  });
  return successor;
}

function normalizeOutpoint(op, label) {
  const transactionId = normalizeHex(op?.transactionId, 32, `${label}.transactionId`);
  const index = Number(op?.index);
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
    fail(`${label}.index out of range`);
  }
  return { transactionId, index };
}

function normalizeFuel(fuel) {
  if (!fuel || typeof fuel !== "object") {
    fail("chain.fuel { outpoint, amount, scriptPublicKeyHex } is required for this operation (ordinary fee UTXO)");
  }
  const scriptPublicKeyHex = String(fuel.scriptPublicKeyHex ?? "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(scriptPublicKeyHex) || scriptPublicKeyHex.length % 2 !== 0) {
    fail("chain.fuel.scriptPublicKeyHex must be hex");
  }
  return {
    outpoint: normalizeOutpoint(fuel.outpoint, "chain.fuel.outpoint"),
    amount: parsePositiveSompi(fuel.amount, "chain.fuel.amount"),
    scriptPublicKeyHex
  };
}

/*
 * Resolve the spending agent's policy + Merkle proof. Either from the
 * FULL agent set (`params.agents` — the canonical tree MUST reproduce the
 * live agentRoot) or from a supplied pre-made policy + proof, verified
 * against the live root. Fail closed on any mismatch.
 */
function resolveAgentProof(state, params) {
  const agentPk = normalizeXOnlyPubkey(params.agentPk, "params.agentPk");
  if (params.agents !== undefined) {
    const tree = buildAgentTreeV4(params.agents);
    if (tree.root !== state.agentRoot) {
      fail("the supplied agent set does not reproduce the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    }
    const proof = generateAgentProofV4(tree, agentPk);
    return { policy: proof.policy, proof };
  }
  if (params.agentPolicy !== undefined && params.agentProof !== undefined) {
    const proof = {
      agentPk,
      root: normalizeHex(params.agentProof.root ?? state.agentRoot, 32, "agentProof.root"),
      siblingsHex: String(params.agentProof.siblingsHex ?? "").toLowerCase(),
      pathBits: parseSompi(params.agentProof.pathBits ?? 0n, "agentProof.pathBits")
    };
    if (proof.root !== state.agentRoot) {
      fail("agent proof root does not match the live agentRoot", "AGENT_ROOT_MISMATCH");
    }
    if (
      !verifyAgentProofV4({ root: state.agentRoot, policy: params.agentPolicy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })
    ) {
      fail("agent proof does not verify for this policy under the live agentRoot", "AGENT_PROOF_INVALID");
    }
    return { policy: params.agentPolicy, proof };
  }
  fail("agentSpend requires either params.agents (full set) or params.agentPolicy + params.agentProof");
}

/*
 * Resolve the recipient membership proof against the AGENT's own
 * recipient root (v0.4 recipients are authorized per agent leaf).
 */
function resolveRecipientProof(agentRecipientRoot, params) {
  const recipient = normalizeHex(params.recipient, 32, "params.recipient");
  let proof;
  if (params.recipients !== undefined) {
    const tree = buildRecipientTree(params.recipients);
    if (tree.root !== agentRecipientRoot) {
      fail("the supplied recipient list does not reproduce this agent's agentRecipientRoot — refusing to build", "RECIPIENT_ROOT_MISMATCH");
    }
    proof = generateRecipientProof(tree, recipient);
  } else if (params.recipientProof !== undefined) {
    proof = {
      recipient,
      root: normalizeHex(params.recipientProof.root, 32, "recipientProof.root"),
      siblingsHex: String(params.recipientProof.siblingsHex ?? "").toLowerCase(),
      pathBits: parseSompi(params.recipientProof.pathBits ?? 0n, "recipientProof.pathBits")
    };
  } else {
    fail("agentSpend requires either params.recipients (full list) or params.recipientProof");
  }
  if (proof.root !== agentRecipientRoot) {
    fail("recipient proof root does not match this agent's agentRecipientRoot", "RECIPIENT_ROOT_MISMATCH");
  }
  if (!verifyRecipientProof({ root: proof.root, recipient, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) {
    fail("recipient proof does not verify for this recipient", "RECIPIENT_PROOF_INVALID");
  }
  return { recipient, proof };
}

/* Owner-operation successor planning (no payment output; fee from fuel). */
function planOwnerOp(state, action, params) {
  switch (action) {
    case "ownerSetAgentRoot": {
      let newRoot;
      if (params.newAgents !== undefined) {
        newRoot = buildAgentTreeV4(params.newAgents).root;
      } else if (params.newAgentRoot !== undefined) {
        newRoot = normalizeHex(params.newAgentRoot, 32, "params.newAgentRoot");
      } else {
        fail("ownerSetAgentRoot requires params.newAgents (canonical set) or params.newAgentRoot");
      }
      return { successor: setAgentRootSuccessorV4(state, newRoot), externalFunding: 0n };
    }
    case "ownerSetApprovers":
      return { successor: setApproversSuccessorV4(state, params.newApprovers ?? {}), externalFunding: 0n };
    case "ownerTopUp": {
      const amount = parsePositiveSompi(params.topUpAmountSompi, "topUpAmountSompi");
      return { successor: topUpSuccessorV4(state, amount), externalFunding: amount };
    }
    case "ownerTopUpReserve": {
      const amount = parsePositiveSompi(params.topUpReserveAmountSompi, "topUpReserveAmountSompi");
      return { successor: topUpReserveSuccessorV4(state, amount), externalFunding: amount };
    }
    case "ownerPause":
      return { successor: pauseSuccessorV4(state, true), externalFunding: 0n };
    case "ownerUnpause":
      return { successor: pauseSuccessorV4(state, false), externalFunding: 0n };
    default:
      fail(`unknown v0.4 owner action ${JSON.stringify(action)} — failing closed`);
  }
}

/* Exact fee for a frozen shape given per-input final sig-script lengths. */
function exactFee(draft, sigScriptLengths) {
  const probe = normalizeFrozenTxV3(draft);
  return calculateRequiredFee(feeDescriptorFromFrozen(probe, sigScriptLengths)).minimumRequiredFee;
}

/*
 * Build (and FREEZE) one v0.4 covenant transition transaction, entirely
 * offline. `chain` supplies the exact predecessor outpoint/value/
 * covenantId and (optionally, for agentSpend; mandatorily, for owner
 * operations) one ordinary fuel UTXO; `changeXOnly` receives fee change.
 */
function buildV4Transaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly }) {
  const version = contractVersion ?? CONTRACT_VERSION_V4;
  const abi = resolveV4Abi(version); // fails closed on any non-v0.4-family version
  const encShape = encoderFunctionShape(abi, action);
  if (!OWNER_ACTIONS.has(action) && !SPEND_ACTIONS.has(action)) {
    fail(`unknown v0.4 action ${JSON.stringify(action)} — failing closed`);
  }
  const template = normalizeTemplateV4(templateInput);

  /* Recovery-mode parse is accepted ONLY for ownerRecover (break-glass). */
  let state;
  if (action === "ownerRecover" && params.allowMalformedState === true) {
    state = normalizeStateV4ForRecovery(stateInput);
  } else {
    state = normalizeStateV4(stateInput);
  }

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.protectedValue + state.feeReserve) {
    fail(
      `chain.predecessorValue ${predecessorValue} != state.protectedValue + state.feeReserve ${state.protectedValue + state.feeReserve} — stale or inconsistent state`,
      "STALE"
    );
  }
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  const terminal = action === "ownerRecover";
  const isSpend = SPEND_ACTIONS.has(action);
  const hasFuel = chain?.fuel !== undefined && chain?.fuel !== null;
  if (!isSpend && !hasFuel) {
    fail(
      "owner operations pin every covenant value (successor/payout value is exact), so the network fee MUST come from an ordinary fuel UTXO — provide chain.fuel",
      "FUEL_REQUIRED"
    );
  }
  const fuel = hasFuel ? normalizeFuel(chain.fuel) : null;

  const current = compileExactStateV4({ config, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const currentSpkHex = String(kaspa.payToScriptHashScript(current.scriptBytes.toString("hex")).script).toLowerCase();
  const encoderPaths = {
    sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(current.buildDir, "constructor-args.json")
  };

  /* --- resolve the transition plan --- */
  let plan;
  let callExtra = {};
  let aboveThreshold = false;
  if (isSpend) {
    const { policy, proof } = resolveAgentProof(state, params);
    const { recipient, proof: rProof } = resolveRecipientProof(
      typeof policy === "object" && policy.agentRecipientRoot
        ? normalizeHex(policy.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot")
        : fail("agent policy is missing agentRecipientRoot"),
      params
    );
    const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");

    /* Funding mode (see the module header). */
    if (!hasFuel && params.reserveConsumedSompi !== undefined) {
      fail("without chain.fuel the reserve consumption IS the exact network fee and is derived by the builder — do not supply reserveConsumedSompi");
    }
    const requestedConsumed = hasFuel ? parseSompi(params.reserveConsumedSompi ?? 0n, "reserveConsumedSompi") : null;

    /*
     * Derive the successor for a candidate reserveConsumed and compute the
     * exact fee for the resulting byte shape. In RESERVE mode iterate to
     * the fixed point reserveConsumed == fee (bounded; the fee depends on
     * the candidate only through the encoded successor-field byte widths).
     */
    const shapeFor = (consumed) => {
      const spend = agentSpendSuccessorV4(state, {
        agentPolicy: policy,
        agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
        payAmount: params.payAmountSompi,
        periodsElapsed: periods,
        reserveConsumed: consumed
      });
      const next = compileExactStateV4({ config, template, state: spend.successor, contractVersion: abi.version });
      const nextSpkHex = String(kaspa.payToScriptHashScript(next.scriptBytes.toString("hex")).script).toLowerCase();
      const spendCallExtra = {
        payAmount: spend.payAmount.toString(),
        agentPk: spend.previousPolicy.agentPk,
        maxPerSpend: spend.previousPolicy.maxPerSpend.toString(),
        periodBudget: spend.previousPolicy.periodBudget.toString(),
        periodLengthDaa: spend.previousPolicy.periodLengthDaa.toString(),
        periodStartDaa: spend.previousPolicy.periodStartDaa.toString(),
        periodSpent: spend.previousPolicy.periodSpent.toString(),
        approvalThreshold: spend.previousPolicy.approvalThreshold.toString(),
        agentMaxFeePerTx: spend.previousPolicy.agentMaxFeePerTx.toString(),
        agentRecipientRoot: spend.previousPolicy.agentRecipientRoot,
        policySiblings: proof.siblingsHex,
        policyPathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString(),
        recipientPk: recipient,
        recipientSiblings: rProof.siblingsHex,
        recipientPathBits: BigInt(rProof.pathBits).toString()
      };
      const budget = selectComputeBudgetV4({ operation: action, aboveThreshold: spend.aboveThreshold });
      const placeholderCall = {
        function: action,
        signature: PLACEHOLDER_SIG_HEX,
        successor: successorCallJsonV4(stateToJsonV4(spend.successor)),
        approvals: placeholderApprovalsBlob(),
        ...spendCallExtra
      };
      const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
      const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;

      const inputs = [
        {
          previousOutpoint: predecessorOutpoint,
          sequence: 0n,
          computeBudget: budget,
          utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n }
        }
      ];
      const sigLens = [covenantSigscriptLen];
      if (fuel) {
        inputs.push({
          previousOutpoint: fuel.outpoint,
          sequence: 0n,
          computeBudget: V4_BUDGET.ORDINARY_INPUT,
          utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n }
        });
        sigLens.push(ORDINARY_SIGSCRIPT_LEN);
      }
      const outputs = [
        { value: spend.payAmount, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recipient) }, covenant: null },
        {
          value: spend.successor.protectedValue + spend.successor.feeReserve,
          scriptPublicKey: { version: 0, scriptHex: nextSpkHex },
          covenant: { authorizingInput: 0, covenantId }
        }
      ];
      if (fuel) {
        outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
      }
      const draft = { version: 1, inputs, outputs, lockTime: spend.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
      const fee = exactFee(draft, sigLens);
      return { spend, next, draft, fee, budget, callHex, covenantSigscriptLen, spendCallExtra, recipient, rProof };
    };

    let shape;
    if (fuel) {
      shape = shapeFor(requestedConsumed);
      if (requestedConsumed > shape.fee) {
        fail(
          `reserveConsumed ${requestedConsumed} exceeds the exact network fee ${shape.fee} — the covenant requires reserveConsumed <= fee; lower reserveConsumedSompi`,
          "RESERVE_OVER_FEE"
        );
      }
      const changeValue = fuel.amount - (shape.fee - requestedConsumed);
      if (changeValue <= 0n) {
        fail(`fuel ${fuel.amount} cannot cover fee ${shape.fee} minus reserveConsumed ${requestedConsumed}`, "INSUFFICIENT_FUEL");
      }
      shape.draft.outputs[2] = { ...shape.draft.outputs[2], value: changeValue };
    } else {
      /* RESERVE mode fixed point: reserveConsumed == exact fee. */
      let consumed = 0n;
      let iterations = 0;
      for (;;) {
        shape = shapeFor(consumed);
        if (shape.fee === consumed) {
          break;
        }
        consumed = shape.fee;
        iterations += 1;
        if (iterations > 4) {
          fail("reserve-funded fee fixed point did not converge — failing closed", "FEE_FIXPOINT");
        }
      }
      if (shape.spend.reserveConsumed !== shape.fee) {
        fail("internal: reserve-funded spend did not consume exactly the network fee");
      }
    }

    aboveThreshold = shape.spend.aboveThreshold;
    callExtra = shape.spendCallExtra;
    plan = {
      kindSpend: true,
      spend: shape.spend,
      successor: shape.spend.successor,
      next: shape.next,
      draft: shape.draft,
      fee: shape.fee,
      budget: shape.budget,
      covenantSigscriptLen: shape.covenantSigscriptLen,
      plannedCallHexLength: shape.callHex.length,
      payment: { xOnly: shape.recipient, value: shape.spend.payAmount },
      recipientProof: shape.rProof,
      agentProof: { root: state.agentRoot, siblingsHex: shape.spend.agentProof.siblingsHex, pathBits: shape.spend.agentProof.pathBits },
      lockTime: shape.spend.lockTime,
      externalFunding: 0n
    };
  } else if (!terminal) {
    const { successor, externalFunding } = planOwnerOp(state, action, params);
    const next = compileExactStateV4({ config, template, state: successor, contractVersion: abi.version });
    const nextSpkHex = String(kaspa.payToScriptHashScript(next.scriptBytes.toString("hex")).script).toLowerCase();
    const budget = selectComputeBudgetV4({ operation: action });
    const placeholderCall = { function: encShape.function, ...encShape.extra, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV4(stateToJsonV4(successor)) };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const inputs = [
      {
        previousOutpoint: predecessorOutpoint,
        sequence: 0n,
        computeBudget: budget,
        utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n }
      },
      {
        previousOutpoint: fuel.outpoint,
        sequence: 0n,
        computeBudget: V4_BUDGET.ORDINARY_INPUT,
        utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n }
      }
    ];
    const outputs = [
      {
        value: successor.protectedValue + successor.feeReserve,
        scriptPublicKey: { version: 0, scriptHex: nextSpkHex },
        covenant: { authorizingInput: 0, covenantId }
      },
      { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
    ];
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
    const changeValue = fuel.amount - fee - externalFunding;
    if (changeValue <= 0n) {
      fail(`fuel ${fuel.amount} cannot cover fee ${fee} + external funding ${externalFunding}`, "INSUFFICIENT_FUEL");
    }
    outputs[1] = { ...outputs[1], value: changeValue };
    plan = {
      kindSpend: false,
      successor,
      next,
      draft: { ...draft, outputs },
      fee,
      budget,
      covenantSigscriptLen,
      plannedCallHexLength: callHex.length,
      payment: null,
      lockTime: 0n,
      externalFunding
    };
  } else {
    /* ownerRecover (terminal): output 0 pinned to the FULL payout. */
    const recover = recoverPlanV4(state, template.owner);
    const budget = selectComputeBudgetV4({ operation: action });
    const placeholderCall = { function: encShape.function, ...encShape.extra, signature: PLACEHOLDER_SIG_HEX };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const inputs = [
      {
        previousOutpoint: predecessorOutpoint,
        sequence: 0n,
        computeBudget: budget,
        utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n }
      },
      {
        previousOutpoint: fuel.outpoint,
        sequence: 0n,
        computeBudget: V4_BUDGET.ORDINARY_INPUT,
        utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n }
      }
    ];
    const outputs = [
      { value: recover.payoutValue, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recover.payoutXOnly) }, covenant: null },
      { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
    ];
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
    const changeValue = fuel.amount - fee;
    if (changeValue <= 0n) {
      fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
    }
    outputs[1] = { ...outputs[1], value: changeValue };
    plan = {
      kindSpend: false,
      terminal: true,
      recover,
      successor: null,
      next: null,
      draft: { ...draft, outputs },
      fee,
      budget,
      covenantSigscriptLen,
      plannedCallHexLength: callHex.length,
      payment: null,
      lockTime: 0n,
      externalFunding: 0n
    };
  }

  if (plan.draft.inputs.length > MAX_TX_FEE_IO || plan.draft.outputs.length > MAX_TX_FEE_IO) {
    fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);
  }

  /* --- FREEZE --- */
  const frozen = normalizeFrozenTxV3(plan.draft);
  const described = describeFrozenTx(frozen);

  /* Value-flow assertions (§E4): the realized fee is exactly the required
   * fee; the successor output carries exactly protected + reserve. */
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== plan.fee) {
    fail("internal: realized fee != required fee");
  }
  if (!plan.terminal) {
    const covOuts = frozen.outputs.filter((o) => o.covenant !== null);
    if (covOuts.length !== 1 || covOuts[0].value !== plan.successor.protectedValue + plan.successor.feeReserve) {
      fail("internal: successor output does not carry exactly protectedValue + feeReserve");
    }
  }

  const successorStateId = plan.terminal ? null : computeStateIdV4({ networkId: config.networkId, template, state: plan.successor, contractVersion: abi.version });
  const reserveConsumed = plan.kindSpend ? plan.spend.reserveConsumed : 0n;
  const externalIn = fuel ? fuel.amount : 0n;
  const externalOut = fuel ? frozen.outputs[frozen.outputs.length - 1].value : 0n;

  return deepFreeze({
    kind: "transition",
    contractVersion: abi.version,
    // The exact encoder entrypoint + selector this build must be finalized
    // with; for v0.4.1 owner ops this is ownerControl + opSelector, not the
    // sdkAction. finalize reuses these so the planned/final bytes match.
    encoderFunction: encShape.function,
    encoderExtra: encShape.extra,
    networkId: config.networkId,
    action,
    role: plan.kindSpend ? "agent" : "owner",
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV4(state),
    successorState: plan.terminal ? null : stateToJsonV4(plan.successor),
    successorStateId,
    successorScriptSha256: plan.terminal ? null : plan.next.scriptSha256,
    /* §E4 explicit fee-reserve accounting for every nonterminal (and the
     * terminal) transaction — all digit strings. */
    accounting: Object.freeze({
      predecessorProtected: state.protectedValue.toString(),
      predecessorFeeReserve: state.feeReserve.toString(),
      payAmount: plan.kindSpend ? plan.spend.payAmount.toString() : "0",
      reserveConsumed: reserveConsumed.toString(),
      externalIn: externalIn.toString(),
      externalOut: externalOut.toString(),
      fee: plan.fee.toString(),
      successorProtected: plan.terminal ? "0" : plan.successor.protectedValue.toString(),
      successorFeeReserve: plan.terminal ? "0" : plan.successor.feeReserve.toString(),
      successorTotal: plan.terminal ? "0" : (plan.successor.protectedValue + plan.successor.feeReserve).toString(),
      terminalPayout: plan.terminal ? plan.recover.payoutValue.toString() : "0"
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    computeBudget: plan.budget,
    requiredFeeSompi: plan.fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: plan.plannedCallHexLength,
    callExtra,
    hasFuelInput: fuel !== null,
    aboveThreshold: plan.kindSpend ? aboveThreshold : false,
    agentProof: plan.kindSpend
      ? Object.freeze({ root: plan.agentProof.root, siblingsHex: plan.agentProof.siblingsHex, pathBits: BigInt(plan.agentProof.pathBits).toString() })
      : null,
    recipientProof: plan.kindSpend
      ? Object.freeze({ root: plan.recipientProof.root, siblingsHex: plan.recipientProof.siblingsHex, pathBits: BigInt(plan.recipientProof.pathBits).toString() })
      : null,
    payment: plan.payment ? { recipient: plan.payment.xOnly, value: plan.payment.value.toString() } : null
  });
}

/*
 * Create the canonical v0.4 approval package for a frozen above-threshold
 * agent-spend build. Fails closed when the build does not require
 * approvals.
 */
function createApprovalPackageForBuildV4(build) {
  if (build.kind !== "transition" || !SPEND_ACTIONS.has(build.action)) {
    fail("approval packages exist only for agent-spend builds");
  }
  if (build.aboveThreshold !== true) {
    fail("this spend is at/below the agent's approvalThreshold — agent authorization is sufficient; do not manufacture approvals");
  }
  return createApprovalPackageV4({
    networkId: build.networkId,
    vaultId: build.template.vaultId,
    predecessorOutpoint: build.predecessorOutpoint,
    predecessorStateId: build.predecessorStateId,
    successorStateId: build.successorStateId,
    policyNonce: build.stateJson.policyNonce,
    predecessorProtectedSompi: build.accounting.predecessorProtected,
    predecessorFeeReserveSompi: build.accounting.predecessorFeeReserve,
    frozenTransaction: build.frozen,
    covenantInputIndex: 0,
    agentPolicy: {
      agentPk: build.callExtra.agentPk,
      maxPerSpend: build.callExtra.maxPerSpend,
      periodBudget: build.callExtra.periodBudget,
      periodLengthDaa: build.callExtra.periodLengthDaa,
      periodStartDaa: build.callExtra.periodStartDaa,
      periodSpent: build.callExtra.periodSpent,
      approvalThreshold: build.callExtra.approvalThreshold,
      agentMaxFeePerTx: build.callExtra.agentMaxFeePerTx,
      agentRecipientRoot: build.callExtra.agentRecipientRoot
    },
    agentProof: build.agentProof,
    successorAgentRoot: build.successorState.agentRoot,
    periodsElapsed: build.callExtra.periodsElapsed,
    recipient: build.payment.recipient,
    payAmountSompi: build.payment.value,
    recipientProof: build.recipientProof,
    reserveConsumedSompi: build.accounting.reserveConsumed,
    approvalM: build.stateJson.approvalM,
    approverSlots: build.stateJson.approverSlots,
    requiredFeeSompi: build.requiredFeeSompi
  });
}

function extractSchnorr65(signatureHex, label) {
  if (typeof signatureHex !== "string" || !/^[0-9a-f]+$/.test(signatureHex)) {
    fail(`${label} must be lowercase hex`, "SIGNATURE_INVALID");
  }
  let sig = signatureHex;
  if (sig.length === 132 && sig.startsWith("41")) {
    sig = sig.slice(2); // strip the 0x41 sigscript push prefix
  }
  if (sig.length !== 130) {
    fail(`${label} has unexpected length ${sig.length / 2} bytes (need 65)`, "SIGNATURE_INVALID");
  }
  if (!sig.endsWith("01")) {
    fail(`${label} sighash byte 0x${sig.slice(-2)} != 0x01 — PolicyVault signs SIG_HASH_ALL only`, "SIGHASH_NOT_ALL");
  }
  return sig;
}

/*
 * FINALIZE a frozen build into the exact broadcast-ready transaction (NO
 * broadcasting here): encode the real covenant call through the
 * production pv_call_encoder and assemble the final signature scripts.
 *
 *   covenantSignatureHex — the agent (spends) or owner (owner ops)
 *     65-byte SIG_HASH_ALL signature over the frozen covenant input;
 *   fuelSignatureScriptHex — the fuel input's complete signature script
 *     (required exactly when the build has a fuel input);
 *   approvalPackage — REQUIRED for above-threshold spends (must be
 *     complete); forbidden otherwise.
 */
function finalizeV4Transaction({ build, covenantSignatureHex, fuelSignatureScriptHex, approvalPackage }) {
  if (build.kind !== "transition" || (build.contractVersion !== CONTRACT_VERSION_V4 && build.contractVersion !== CONTRACT_VERSION_V4_1)) {
    fail("finalizeV4Transaction takes a v0.4 or v0.4.1 transition build");
  }
  const covenantSig = extractSchnorr65(covenantSignatureHex, "covenant signature");
  const terminal = build.action === "ownerRecover";

  // Use the exact encoder entrypoint + selector the build planned with (for
  // v0.4.1 owner ops this is ownerControl + opSelector, not the sdkAction).
  const call = { function: build.encoderFunction ?? build.action, ...(build.encoderExtra ?? {}), signature: covenantSig, ...build.callExtra };
  if (!terminal) {
    call.successor = successorCallJsonV4(build.successorState);
  }
  if (SPEND_ACTIONS.has(build.action)) {
    if (build.aboveThreshold) {
      if (!approvalPackage) {
        fail("above-threshold agent spend requires a complete approval package", "INSUFFICIENT_APPROVALS");
      }
      if (approvalPackage.txId !== build.txId) {
        fail("approval package txId does not match this build — packages are bound to one exact frozen transaction", "PACKAGE_MISMATCH");
      }
      call.approvals = approvalsBlobV4(approvalPackage); // integrity + completeness enforced inside
    } else {
      if (approvalPackage) {
        fail("at/below-threshold agent spends carry the canonical placeholder blob, not an approval package");
      }
      call.approvals = placeholderApprovalsBlob();
    }
  } else if (approvalPackage) {
    fail(`${build.action} does not take approvals`);
  }

  const callHex = runEncoderV4({
    sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
    call,
    contractVersion: build.contractVersion
  });
  if (callHex.length !== build.plannedCallHexLength) {
    fail(
      `final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`,
      "FEE_DRIFT"
    );
  }

  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const covenantScript = covenantSigscript(callHex, Buffer.from(artifact.script));

  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantScript;
  if (build.hasFuelInput) {
    if (
      typeof fuelSignatureScriptHex !== "string" ||
      !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) ||
      fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN
    ) {
      fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
    }
    json.inputs[1].signatureScript = fuelSignatureScriptHex;
  } else if (fuelSignatureScriptHex !== undefined) {
    fail("this build has no fuel input — do not supply a fuel signature");
  }

  return Object.freeze({
    txId: build.txId, // v1 txId excludes signature scripts — unchanged by finalize
    requiredFeeSompi: build.requiredFeeSompi,
    finalTransaction: json,
    covenantCallHex: callHex
  });
}

/*
 * GENESIS construction (v0.4 vault creation — NOT a covenant entrypoint):
 * ordinary funding inputs -> [vault P2SH covenant output holding
 * protectedValue + feeReserve, optional agent fuel, change]. The genesis
 * covenantId is computed with the real rusty-kaspa covenantId() over the
 * first input's outpoint and the UNBOUND vault output, exactly as the
 * hardened v0.2/v0.3 flows do.
 */
function buildCreateV4({ config, templateInput, initialStateInput, funding, changeXOnly, agentFuel, contractVersion }) {
  const abi = resolveV4Abi(contractVersion); // fails closed on unknown versions
  const template = normalizeTemplateV4(templateInput);
  const state = normalizeStateV4(initialStateInput);
  if (state.policyNonce !== 0n) {
    fail("a v0.4 genesis state must carry policyNonce 0");
  }
  if (state.paused !== 0n) {
    fail("a v0.4 genesis state must start unpaused");
  }

  if (!Array.isArray(funding) || funding.length === 0) {
    fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  }
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) {
      fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    }
    return {
      outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`),
      amount: parsePositiveSompi(f.amount, `funding[${i}].amount`),
      scriptPublicKeyHex: spk
    };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  let fuelOut = null;
  if (agentFuel !== undefined && agentFuel !== null) {
    fuelOut = {
      xOnly: normalizeXOnlyPubkey(agentFuel.xOnly, "agentFuel.xOnly"),
      amount: parsePositiveSompi(agentFuel.amountSompi, "agentFuel.amountSompi")
    };
  }

  const compiled = compileExactStateV4({ config, template, state, contractVersion: abi.version });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const vaultValue = state.protectedValue + state.feeReserve;

  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const vaultSpkHex = String(kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")).script).toLowerCase();

  const outputs = [];
  const vaultOutputIndex = 0;
  outputs.push({ value: vaultValue, scriptPublicKey: { version: 0, scriptHex: vaultSpkHex }, covenant: null });
  if (fuelOut) {
    outputs.push({ value: fuelOut.amount, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(fuelOut.xOnly) }, covenant: null });
  }
  const changeIndex = outputs.length;
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });

  /* Genesis covenantId from the REAL rusty-kaspa wasm implementation:
   * first input outpoint + the unbound vault output at its index. */
  const unbound = new kaspa.TransactionOutput(vaultValue, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
  const genesisCovenantId = kaspa
    .covenantId(
      { transactionId: fundingInputs[0].outpoint.transactionId, index: fundingInputs[0].outpoint.index },
      [{ index: vaultOutputIndex, output: unbound }]
    )
    .toString()
    .toLowerCase();
  outputs[vaultOutputIndex] = { ...outputs[vaultOutputIndex], covenant: { authorizingInput: 0, covenantId: genesisCovenantId } };

  const inputs = fundingInputs.map((f) => ({
    previousOutpoint: f.outpoint,
    sequence: 0n,
    computeBudget: V4_BUDGET.ORDINARY_INPUT,
    utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n }
  }));

  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const requiredFee = exactFee(draft, inputs.map(() => ORDINARY_SIGSCRIPT_LEN));

  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - vaultValue - (fuelOut ? fuelOut.amount : 0n) - requiredFee;
  if (changeValue <= 0n) {
    fail(`funding ${totalFunding} cannot cover deposit ${vaultValue} + fuel ${fuelOut ? fuelOut.amount : 0n} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  }
  outputs[changeIndex] = { ...outputs[changeIndex], value: changeValue };

  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  const described = describeFrozenTx(frozen);

  return deepFreeze({
    kind: "genesis",
    contractVersion: abi.version,
    networkId: config.networkId,
    action: "createVault",
    template,
    initialState: stateToJsonV4(state),
    stateId,
    vaultOutputIndex,
    changeIndex,
    covenantId: genesisCovenantId,
    scriptSha256: compiled.scriptSha256,
    vaultScriptHex: compiled.scriptHex,
    accounting: Object.freeze({
      protectedValue: state.protectedValue.toString(),
      feeReserve: state.feeReserve.toString(),
      vaultValue: vaultValue.toString()
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}

module.exports = {
  buildV4Transaction,
  buildCreateV4,
  createApprovalPackageForBuildV4,
  finalizeV4Transaction,
  successorCallJsonV4,
  runEncoderV4,
  ENCODER_PATH,
  PLACEHOLDER_SIG_HEX,
  MAX_TX_FEE_IO
};
