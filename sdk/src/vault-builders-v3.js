"use strict";

/*
 * PolicyVault v0.3 OFFLINE transaction builders (Phase 4H).
 *
 * Deterministic, fully-offline construction of the genesis transaction and
 * all 11 production covenant entrypoints:
 *
 *   delegateSpend, rolloverAndSpend, ownerPause, ownerUnpause,
 *   revokeDelegate, rotateDelegate, ownerTopUp, migratePolicy,
 *   ownerSetRecipientRoot, ownerSetApprovers, ownerRecover
 *
 * Pipeline discipline (builders NEVER broadcast; no network access here):
 *
 *   1. normalize the predecessor (strict; recovery-parse ONLY for
 *      ownerRecover);
 *   2. derive the single canonical successor (vault-transitions-v3);
 *   3. compile the exact predecessor/successor states (silverc);
 *   4. select the proven-safe compute budget (compute-budget-v3);
 *   5. compute the EXACT fee from the final shape: the covenant call is
 *      encoded through the REAL pv_call_encoder with fixed-width
 *      placeholder signatures (65-byte sig, 650-byte approvals blob), so
 *      the sig-script length at fee time equals the final length exactly;
 *   6. FREEZE the transaction (frozen-tx-v3) — txId + covenant sighash
 *      from real consensus code; every sighash-visible field is now
 *      immutable;
 *   7. (above threshold) create the approval package and collect
 *      approvals against the frozen transaction;
 *   8. finalize: encode the real covenant call (delegate/owner signature +
 *      approvals blob) through the SAME production encoder and assemble
 *      the exact final signature scripts. Finalize ASSERTS the call length
 *      matches the fee-time length and never touches a frozen field.
 *
 * Network fees are funded ONLY from the ordinary fuel input; protected
 * principal moves only by the exact payment / top-up / recovery amount.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex } = require("./vault-state");
const {
  CONTRACT_VERSION_V3,
  MAX_APPROVERS,
  normalizeTemplateV3,
  normalizeStateV3,
  normalizeStateV3ForRecovery,
  computeStateIdV3,
  stateToJsonV3
} = require("./vault-state-v3");
const { compileExactStateV3 } = require("./contract-compiler-v3");
const {
  spendSuccessorV3,
  rolloverSuccessorV3,
  pauseSuccessorV3,
  revokeSuccessorV3,
  rotateSuccessorV3,
  topUpSuccessorV3,
  migrateSuccessorV3,
  setRecipientRootSuccessorV3,
  setApproversSuccessorV3,
  recoverPlanV3
} = require("./vault-transitions-v3");
const { selectComputeBudgetV3, V3_BUDGET } = require("./compute-budget-v3");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { covenantSigscript } = require("./spend-vault");
const { createApprovalPackageV3, placeholderApprovalsBlob, approvalsBlobV3, p2pkScriptHex } = require("./approval-package-v3");

const ENCODER_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder");
const PLACEHOLDER_SIG_HEX = "00".repeat(65);
const ORDINARY_SIGSCRIPT_LEN = 66; // 0x41 push + 65-byte Schnorr signature

const OWNER_ACTIONS = new Set([
  "ownerPause",
  "ownerUnpause",
  "revokeDelegate",
  "rotateDelegate",
  "ownerTopUp",
  "migratePolicy",
  "ownerSetRecipientRoot",
  "ownerSetApprovers",
  "ownerRecover"
]);
const SPEND_ACTIONS = new Set(["delegateSpend", "rolloverAndSpend"]);

function fail(message, code) {
  const error = new Error(`vault-builders-v3: ${message}`);
  if (code) error.code = code;
  throw error;
}

function runEncoderV3({ sourcePath, constructorArgsPath, call }) {
  if (!fs.existsSync(ENCODER_PATH)) {
    fail(`pv_call_encoder not built: ${ENCODER_PATH}`);
  }
  const callPath = path.join(os.tmpdir(), `pv3-call-${process.pid}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(callPath, JSON.stringify({ ...call, contractVersion: CONTRACT_VERSION_V3 }), { mode: 0o600 });
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

/* The v0.3 successor object in the encoder's call.json field names. */
function successorCallJsonV3(stateJson) {
  const successor = {
    protectedValue: stateJson.protectedValue,
    periodStartDaa: stateJson.periodStartDaa,
    periodSpent: stateJson.periodSpent,
    paused: Number(stateJson.paused),
    delegate: stateJson.delegate,
    delegateActive: Number(stateJson.delegateActive),
    maxPerSpend: stateJson.maxPerSpend,
    periodBudget: stateJson.periodBudget,
    periodLengthDaa: stateJson.periodLengthDaa,
    recipientRoot: stateJson.recipientRoot,
    approvalM: stateJson.approvalM,
    approvalThresholdAmount: stateJson.approvalThresholdAmount,
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
    fail("chain.fuel { outpoint, amount, scriptPublicKeyHex } is required (ordinary fee UTXO)");
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
 * Resolve action + params into the transition plan: canonical successor
 * (or terminal recover plan), encoder call extra fields, payment output,
 * lock time, external funding, and the approval-tier decision.
 */
function planV3(template, state, action, params) {
  if (SPEND_ACTIONS.has(action)) {
    const pay = parsePositiveSompi(params.payAmountSompi, "payAmountSompi");
    const recipient = normalizeHex(params.recipient, 32, "recipient");

    /* Recipient proof: either derived from the full recipient list (the
     * canonical tree MUST reproduce the live recipientRoot) or supplied
     * pre-made and verified against the live root. Fail closed on any
     * mismatch — a proof that does not match the live root cannot spend. */
    let proof;
    if (params.recipients !== undefined) {
      const tree = buildRecipientTree(params.recipients);
      if (tree.root !== state.recipientRoot) {
        fail("the supplied recipient list does not reproduce the live recipientRoot — refusing to build", "RECIPIENT_ROOT_MISMATCH");
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
      fail("spend requires either params.recipients (full list) or params.recipientProof");
    }
    if (proof.root !== state.recipientRoot) {
      fail("recipient proof root does not match the live recipientRoot", "RECIPIENT_ROOT_MISMATCH");
    }
    if (!verifyRecipientProof({ root: proof.root, recipient, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) {
      fail("recipient proof does not verify for this recipient", "RECIPIENT_PROOF_INVALID");
    }

    const aboveThreshold = pay > state.approvalThresholdAmount;
    if (action === "delegateSpend") {
      const successor = spendSuccessorV3(state, pay);
      return {
        successor,
        role: "delegate",
        payment: { xOnly: recipient, value: pay },
        lockTime: 0n,
        externalFunding: 0n,
        aboveThreshold,
        proof,
        callExtra: {
          payAmount: pay.toString(),
          recipientPk: recipient,
          siblings: proof.siblingsHex,
          pathBits: BigInt(proof.pathBits).toString()
        }
      };
    }
    const periods = parseSompi(params.periodsElapsed, "periodsElapsed");
    const successor = rolloverSuccessorV3(state, pay, periods);
    return {
      successor,
      role: "delegate",
      payment: { xOnly: recipient, value: pay },
      lockTime: successor.periodStartDaa,
      externalFunding: 0n,
      aboveThreshold,
      proof,
      callExtra: {
        payAmount: pay.toString(),
        recipientPk: recipient,
        siblings: proof.siblingsHex,
        pathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString()
      }
    };
  }

  switch (action) {
    case "ownerPause":
      return { successor: pauseSuccessorV3(state, true), role: "owner", payment: null, lockTime: 0n, externalFunding: 0n, callExtra: {} };
    case "ownerUnpause":
      return { successor: pauseSuccessorV3(state, false), role: "owner", payment: null, lockTime: 0n, externalFunding: 0n, callExtra: {} };
    case "revokeDelegate":
      return { successor: revokeSuccessorV3(state), role: "owner", payment: null, lockTime: 0n, externalFunding: 0n, callExtra: {} };
    case "rotateDelegate":
      return { successor: rotateSuccessorV3(state, params.newDelegate), role: "owner", payment: null, lockTime: 0n, externalFunding: 0n, callExtra: {} };
    case "ownerTopUp": {
      const amount = parsePositiveSompi(params.topUpAmountSompi, "topUpAmountSompi");
      return {
        successor: topUpSuccessorV3(state, amount),
        role: "owner",
        payment: null,
        lockTime: 0n,
        externalFunding: amount,
        callExtra: {}
      };
    }
    case "migratePolicy":
      return { successor: migrateSuccessorV3(state, params.newPolicy ?? {}), role: "owner", payment: null, lockTime: 0n, externalFunding: 0n, callExtra: {} };
    case "ownerSetRecipientRoot":
      return {
        successor: setRecipientRootSuccessorV3(state, params.newRecipientRoot),
        role: "owner",
        payment: null,
        lockTime: 0n,
        externalFunding: 0n,
        callExtra: {}
      };
    case "ownerSetApprovers":
      return {
        successor: setApproversSuccessorV3(state, params.newApprovers ?? {}),
        role: "owner",
        payment: null,
        lockTime: 0n,
        externalFunding: 0n,
        callExtra: {}
      };
    case "ownerRecover": {
      const plan = recoverPlanV3(state, template.owner);
      return { successor: null, terminal: true, recover: plan, role: "owner", payment: null, lockTime: 0n, externalFunding: 0n, callExtra: {} };
    }
    default:
      fail(`unknown v0.3 action ${JSON.stringify(action)} — failing closed`);
  }
}

/*
 * Build (and FREEZE) one v0.3 covenant transition transaction, entirely
 * offline. `chain` supplies the exact predecessor outpoint/covenantId and
 * one ordinary fuel UTXO; `changeXOnly` receives fee change.
 *
 * Returns the frozen build: { action, frozen, txId, covenantSighash,
 * computeBudget, requiredFeeSompi, successorState(+Id), encoder paths,
 * plannedCallHexLength, aboveThreshold, approvalContext }.
 */
function buildV3Transaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly }) {
  const version = contractVersion ?? CONTRACT_VERSION_V3;
  if (version !== CONTRACT_VERSION_V3) {
    fail(`unsupported contractVersion ${JSON.stringify(version)} for the v0.3 builder — failing closed (no cross-version fallback)`);
  }
  if (!OWNER_ACTIONS.has(action) && !SPEND_ACTIONS.has(action)) {
    fail(`unknown v0.3 action ${JSON.stringify(action)} — failing closed`);
  }
  const template = normalizeTemplateV3(templateInput);

  /* Recovery-mode parse is accepted ONLY for ownerRecover (break-glass). */
  let state;
  if (action === "ownerRecover" && params.allowMalformedState === true) {
    state = normalizeStateV3ForRecovery(stateInput);
  } else {
    state = normalizeStateV3(stateInput);
  }

  const plan = planV3(template, state, action, params);
  const terminal = plan.terminal === true;

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const fuel = normalizeFuel(chain?.fuel);
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.protectedValue) {
    fail(`chain.predecessorValue ${predecessorValue} != state.protectedValue ${state.protectedValue} — stale or inconsistent state`, "STALE");
  }

  const current = compileExactStateV3({ config, template, state });
  const next = terminal ? null : compileExactStateV3({ config, template, state: plan.successor });
  const successorStateId = terminal ? null : computeStateIdV3({ networkId: config.networkId, template, state: plan.successor });

  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const currentSpkHex = String(kaspa.payToScriptHashScript(current.scriptBytes.toString("hex")).script).toLowerCase();
  const nextSpkHex = terminal ? null : String(kaspa.payToScriptHashScript(next.scriptBytes.toString("hex")).script).toLowerCase();

  const computeBudget = selectComputeBudgetV3({
    operation: action,
    aboveThreshold: SPEND_ACTIONS.has(action) ? plan.aboveThreshold : undefined
  });

  /* --- exact fee from the KNOWN final signature-script lengths --- */
  const encoderPaths = {
    sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(current.buildDir, "constructor-args.json")
  };
  const placeholderCall = { function: action, signature: PLACEHOLDER_SIG_HEX, ...plan.callExtra };
  if (!terminal) {
    placeholderCall.successor = successorCallJsonV3(stateToJsonV3(plan.successor));
  }
  if (SPEND_ACTIONS.has(action)) {
    placeholderCall.approvals = placeholderApprovalsBlob();
  }
  const placeholderCallHex = runEncoderV3({ ...encoderPaths, call: placeholderCall });
  const covenantSigscriptLen = covenantSigscript(placeholderCallHex, current.scriptBytes).length / 2;

  /* --- outputs (change patched after the exact fee) --- */
  const outputs = [];
  if (plan.payment) {
    outputs.push({ value: plan.payment.value, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(plan.payment.xOnly) }, covenant: null });
  }
  let successorIndex = null;
  let payoutIndex = null;
  if (terminal) {
    payoutIndex = outputs.length;
    outputs.push({
      value: plan.recover.payoutValue,
      scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(plan.recover.payoutXOnly) },
      covenant: null
    });
  } else {
    successorIndex = outputs.length;
    outputs.push({
      value: plan.successor.protectedValue,
      scriptPublicKey: { version: 0, scriptHex: nextSpkHex },
      covenant: { authorizingInput: 0, covenantId }
    });
  }
  const changeIndex = outputs.length;
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });

  const inputs = [
    {
      previousOutpoint: predecessorOutpoint,
      sequence: 0n,
      computeBudget,
      utxo: { amount: state.protectedValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n }
    },
    {
      previousOutpoint: fuel.outpoint,
      sequence: 0n,
      computeBudget: V3_BUDGET.ORDINARY_INPUT,
      utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n }
    }
  ];

  const draft = { version: 1, inputs, outputs, lockTime: plan.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const feeProbe = normalizeFrozenTxV3(draft);
  const requiredFee = calculateRequiredFee(
    feeDescriptorFromFrozen(feeProbe, [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN])
  ).minimumRequiredFee;

  const changeValue = fuel.amount - requiredFee - plan.externalFunding;
  if (changeValue <= 0n) {
    fail(`fuel ${fuel.amount} cannot cover fee ${requiredFee} + external funding ${plan.externalFunding}`, "INSUFFICIENT_FUEL");
  }
  outputs[changeIndex] = { ...outputs[changeIndex], value: changeValue };

  /* --- FREEZE --- */
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  const described = describeFrozenTx(frozen);

  /* Value-flow assertion: network fee comes ONLY from fuel; principal
   * moves only by the payment / top-up / payout amount. */
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== requiredFee) {
    fail("internal: realized fee != required fee");
  }

  return Object.freeze({
    kind: "transition",
    contractVersion: CONTRACT_VERSION_V3,
    networkId: config.networkId,
    action,
    role: plan.role,
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV3(state),
    successorState: terminal ? null : stateToJsonV3(plan.successor),
    successorStateId,
    successorIndex,
    payoutIndex,
    changeIndex,
    successorScriptSha256: terminal ? null : next.scriptSha256,
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    computeBudget,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: placeholderCallHex.length,
    callExtra: plan.callExtra,
    aboveThreshold: SPEND_ACTIONS.has(action) ? plan.aboveThreshold : false,
    recipientProof: SPEND_ACTIONS.has(action)
      ? { root: plan.proof.root, siblingsHex: plan.proof.siblingsHex, pathBits: BigInt(plan.proof.pathBits).toString() }
      : null,
    payment: plan.payment ? { recipient: plan.payment.xOnly, value: plan.payment.value.toString() } : null
  });
}

/*
 * Create the canonical approval package for a frozen above-threshold
 * spend build. Fails closed when the build does not require approvals.
 */
function createApprovalPackageForBuild(build) {
  if (build.kind !== "transition" || !SPEND_ACTIONS.has(build.action)) {
    fail("approval packages exist only for spend builds");
  }
  if (build.aboveThreshold !== true) {
    fail("this spend is at/below approvalThresholdAmount — delegate authorization is sufficient; do not manufacture approvals");
  }
  return createApprovalPackageV3({
    networkId: build.networkId,
    vaultId: build.template.vaultId,
    action: build.action,
    predecessorOutpoint: build.predecessorOutpoint,
    predecessorStateId: build.predecessorStateId,
    successorStateId: build.successorStateId,
    policyNonce: build.stateJson.policyNonce,
    frozenTransaction: build.frozen,
    covenantInputIndex: 0,
    recipient: build.payment.recipient,
    payAmountSompi: build.payment.value,
    recipientProof: build.recipientProof,
    approvalThresholdAmount: build.stateJson.approvalThresholdAmount,
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
 *   covenantSignatureHex — the delegate (spends) or owner (owner ops)
 *     65-byte SIG_HASH_ALL signature over the frozen covenant input;
 *   fuelSignatureScriptHex — the fuel input's complete signature script;
 *   approvalPackage — REQUIRED for above-threshold spends (must be
 *     complete); forbidden otherwise.
 */
function finalizeV3Transaction({ build, covenantSignatureHex, fuelSignatureScriptHex, approvalPackage }) {
  if (build.kind !== "transition") {
    fail("finalizeV3Transaction takes a transition build");
  }
  const covenantSig = extractSchnorr65(covenantSignatureHex, "covenant signature");
  const terminal = build.action === "ownerRecover";

  const call = { function: build.action, signature: covenantSig, ...build.callExtra };
  if (!terminal) {
    call.successor = successorCallJsonV3(build.successorState);
  }
  if (SPEND_ACTIONS.has(build.action)) {
    if (build.aboveThreshold) {
      if (!approvalPackage) {
        fail("above-threshold spend requires a complete approval package", "INSUFFICIENT_APPROVALS");
      }
      if (approvalPackage.txId !== build.txId) {
        fail("approval package txId does not match this build — packages are bound to one exact frozen transaction", "PACKAGE_MISMATCH");
      }
      call.approvals = approvalsBlobV3(approvalPackage); // integrity + completeness enforced inside
    } else {
      if (approvalPackage) {
        fail("at/below-threshold spends carry the canonical placeholder blob, not an approval package");
      }
      call.approvals = placeholderApprovalsBlob();
    }
  } else if (approvalPackage) {
    fail(`${build.action} does not take approvals`);
  }

  const callHex = runEncoderV3({
    sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
    call
  });
  if (callHex.length !== build.plannedCallHexLength) {
    fail(
      `final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`,
      "FEE_DRIFT"
    );
  }

  const redeemBytes = fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json"));
  const artifact = JSON.parse(redeemBytes);
  const covenantScript = covenantSigscript(callHex, Buffer.from(artifact.script));

  if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) {
    fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
  }

  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantScript;
  json.inputs[1].signatureScript = fuelSignatureScriptHex;

  return Object.freeze({
    txId: build.txId, // v1 txId excludes signature scripts — unchanged by finalize
    requiredFeeSompi: build.requiredFeeSompi,
    finalTransaction: json,
    covenantCallHex: callHex
  });
}

/*
 * GENESIS construction (v0.3 vault creation — NOT a covenant entrypoint):
 * ordinary funding inputs -> [vault P2SH covenant output, optional
 * delegate fuel, change]. The genesis covenantId is computed with the
 * real rusty-kaspa covenantId() over the first input's outpoint and the
 * UNBOUND vault output, exactly as the hardened v0.2 flow does.
 */
function buildCreateV3({ config, templateInput, initialStateInput, funding, changeXOnly, delegateFuelSompi = "0" }) {
  const template = normalizeTemplateV3(templateInput);
  const state = normalizeStateV3(initialStateInput);
  if (state.policyNonce !== 0n) {
    fail("a v0.3 genesis state must carry policyNonce 0");
  }
  if (state.periodSpent !== 0n) {
    fail("a v0.3 genesis state must carry periodSpent 0");
  }
  if (state.paused !== 0n || state.delegateActive !== 1n) {
    fail("a v0.3 genesis state must start unpaused with an active delegate");
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
  const delegateFuel = parseSompi(delegateFuelSompi, "delegateFuelSompi");

  const compiled = compileExactStateV3({ config, template, state });
  const stateId = computeStateIdV3({ networkId: config.networkId, template, state });

  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const vaultSpkHex = String(kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")).script).toLowerCase();

  const outputs = [];
  const vaultOutputIndex = 0;
  outputs.push({ value: state.protectedValue, scriptPublicKey: { version: 0, scriptHex: vaultSpkHex }, covenant: null });
  if (delegateFuel > 0n) {
    outputs.push({ value: delegateFuel, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(state.delegate) }, covenant: null });
  }
  const changeIndex = outputs.length;
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });

  /* Genesis covenantId from the REAL rusty-kaspa wasm implementation:
   * first input outpoint + the unbound vault output at its index. */
  const unbound = new kaspa.TransactionOutput(state.protectedValue, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
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
    computeBudget: V3_BUDGET.ORDINARY_INPUT,
    utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n }
  }));

  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const feeProbe = normalizeFrozenTxV3(draft);
  const requiredFee = calculateRequiredFee(
    feeDescriptorFromFrozen(feeProbe, inputs.map(() => ORDINARY_SIGSCRIPT_LEN))
  ).minimumRequiredFee;

  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - state.protectedValue - delegateFuel - requiredFee;
  if (changeValue <= 0n) {
    fail(`funding ${totalFunding} cannot cover deposit ${state.protectedValue} + fuel ${delegateFuel} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  }
  outputs[changeIndex] = { ...outputs[changeIndex], value: changeValue };

  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  const described = describeFrozenTx(frozen);

  return Object.freeze({
    kind: "genesis",
    contractVersion: CONTRACT_VERSION_V3,
    networkId: config.networkId,
    action: "createVault",
    template,
    initialState: stateToJsonV3(state),
    stateId,
    vaultOutputIndex,
    changeIndex,
    covenantId: genesisCovenantId,
    scriptSha256: compiled.scriptSha256,
    vaultScriptHex: compiled.scriptHex,
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}

module.exports = {
  buildV3Transaction,
  buildCreateV3,
  createApprovalPackageForBuild,
  finalizeV3Transaction,
  successorCallJsonV3,
  runEncoderV3,
  ENCODER_PATH,
  PLACEHOLDER_SIG_HEX
};
