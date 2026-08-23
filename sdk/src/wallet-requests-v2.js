"use strict";

/*
 * Signer-agnostic wallet request pipeline for PolicyVault v0.2.
 *
 * Splits the hardened transition pipeline into a BUILD stage (no key, no
 * broadcast) and a FINALIZE-and-SUBMIT stage that accepts wallet-produced
 * authorization material. The signer only signs transaction inputs and
 * returns signed Safe JSON — exactly KasWare's `signPskt` contract — so any
 * wallet/HSM/agent adapter feeds the same canonical request. No consensus-
 * visible byte logic lives in the signer; the covenant-call encoding, exact
 * fee, claims, submission and reconciliation all run in this hardened path.
 *
 * Durable request state machine (persisted under data/requests/<id>.json):
 *   BUILT -> SIGNED -> FINALIZED -> SUBMITTING -> SUBMITTED -> CHAIN_VERIFIED
 * Fail-closed terminal/actionable states:
 *   WALLET_REJECTED, SIGNATURE_INVALID, PREFLIGHT_FAILED, STALE,
 *   CLAIM_CONFLICT, SUBMISSION_FAILED, SUBMISSION_REJECTED (definitive
 *   node rejection — claims auto-released on chain evidence),
 *   AUTHORIZATION_FAILED / NOT_OWNER / NOT_DELEGATE (signer not
 *   authorized for the action — nothing durable is created),
 *   RECONCILIATION_REQUIRED, TERMINATED_UNKNOWN, BUILD_FAILED
 *
 * The exact fee is computed at BUILD time from the KNOWN final
 * signature-script lengths (fixed-width Schnorr + fixed covenant-call
 * fields), so the wallet signs the final transaction ONCE and the realized
 * fee is exact — the same guarantee finalizeWithExactFee gives the headless
 * path, without a second interactive signature.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { persistJsonDurably, readJsonStrict } = require("./durable-json");
const {
  CONTRACT_VERSION_V2,
  spendSuccessorV2,
  rolloverSuccessorV2,
  pauseSuccessorV2,
  revokeSuccessorV2,
  rotateSuccessorV2,
  topUpSuccessorV2,
  migrateSuccessorV2,
  computeStateIdV2,
  stateToJson
} = require("./vault-state-v2");
const { compileExactStateV2 } = require("./contract-compiler-v2");
const { normalizeTemplateV2, normalizeStateV2 } = require("./vault-state-v2");
const { MANIFEST_SCHEMA_V2 } = require("./manifest-v2");
const { CONTRACT_VERSION_V2: CONTRACT_V2 } = require("./vault-state-v2");
const { covenantAddress, connectVerified, getAddressUtxos } = require("./chain");
const { calculateRequiredFee, describeWasmTransaction } = require("./fee-mass");
const { claimTransition, claimSubmission, persistReceipt, releaseTransitionClaim, releaseSubmissionClaim } = require("./submission-claim");
const { resolveAddressIdentity } = require("./address-identity");
const { proveExpectedEffect } = require("./reconcile-v2");
const { loadManifestV2, persistManifestV2 } = require("./manifest-v2");
const { VaultStatus } = require("./manifest");
const { covenantSigscript } = require("./spend-vault");
const { sompiToKas } = require("./amounts");
const { appendAudit } = require("./audit");

const ENCODER_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder");
const REQUEST_SCHEMA = "policyvault-wallet-request/v2";
const V2_COVENANT_COMPUTE_BUDGET = 20;
const FEE_INPUT_COMPUTE_BUDGET = 10;
const FEE_PLACEHOLDER_SOMPI = 5_000_000n;
const PLACEHOLDER_SIG_HEX = "00".repeat(65);

const RequestState = Object.freeze({
  BUILT: "BUILT",
  SIGNED: "SIGNED",
  FINALIZED: "FINALIZED",
  SUBMITTING: "SUBMITTING",
  SUBMITTED: "SUBMITTED",
  CHAIN_VERIFIED: "CHAIN_VERIFIED",
  WALLET_REJECTED: "WALLET_REJECTED",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  PREFLIGHT_FAILED: "PREFLIGHT_FAILED",
  STALE: "STALE",
  CLAIM_CONFLICT: "CLAIM_CONFLICT",
  SUBMISSION_FAILED: "SUBMISSION_FAILED",
  SUBMISSION_REJECTED: "SUBMISSION_REJECTED",
  AUTHORIZATION_FAILED: "AUTHORIZATION_FAILED",
  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
  TERMINATED_UNKNOWN: "TERMINATED_UNKNOWN",
  BUILD_FAILED: "BUILD_FAILED"
});

/*
 * Signer role required for each action — the single source consulted
 * BEFORE any transaction construction. Unknown actions fail closed.
 */
const ROLE_BY_ACTION = Object.freeze({
  delegateSpend: "delegate",
  rolloverAndSpend: "delegate",
  ownerPause: "owner",
  ownerUnpause: "owner",
  revokeDelegate: "owner",
  rotateDelegate: "owner",
  ownerTopUp: "owner",
  migratePolicy: "owner",
  ownerRecover: "owner"
});

/*
 * Authorization gate (motivating incident: a delegate-signed ownerTopUp
 * reached build/sign/claim/submit and stranded a transition claim,
 * 2026-08-16, request 9f6702ed…). The connected signer's canonical
 * identity — resolved from its wallet address through the shared address
 * boundary — must equal the exact key the covenant will enforce for the
 * requested role. Runs BEFORE construction at BUILD and again against the
 * current manifest at FINALIZE. The UI's role filtering is convenience
 * only; this check is mandatory regardless.
 */
function assertSignerAuthorized(config, { role, signerAddress, template, state, action }) {
  let signerXOnly;
  try {
    signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  } catch (e) {
    throw fail(`signer address rejected: ${e.message}`, "AUTHORIZATION_FAILED");
  }
  if (role === "owner") {
    if (signerXOnly !== template.owner) {
      throw fail(`${action} is an owner operation; the connected wallet is not this vault's owner`, "NOT_OWNER");
    }
    return signerXOnly;
  }
  if (role === "delegate") {
    const delegate = typeof state.delegate === "string" ? state.delegate : stateToJson(state).delegate;
    if (signerXOnly !== delegate) {
      throw fail(`${action} is a delegate operation; the connected wallet is not this vault's delegate`, "NOT_DELEGATE");
    }
    return signerXOnly;
  }
  throw fail(`unknown signer role ${role} — failing closed`, "AUTHORIZATION_FAILED");
}

/*
 * Submission-outcome classification. DEFINITIVE = the node evaluated the
 * transaction and rejected it; rusty-kaspa wraps every such rejection as
 * "Rejected transaction {id}: {reason}" (rpc/core/src/error.rs
 * RpcError::RejectedTransaction). Transport failures (timeout, dropped
 * connection, crash) never carry that prefix and stay AMBIGUOUS: claims
 * are kept and reconciliation decides from chain evidence.
 */
function isDefinitiveSubmitRejection(message) {
  return /^(wallet-requests-v2: submit failed: )?Rejected transaction /i.test(String(message ?? ""));
}

/* TEST-ONLY submission-error injection (never on mainnet). */
function maybeInjectSubmitError(config, txId) {
  const mode = process.env.PV_TEST_WALLET_SUBMIT_ERROR;
  if (!mode) return;
  if (config.networkId === "mainnet") {
    throw fail("PV_TEST_WALLET_SUBMIT_ERROR must never be armed on mainnet", "BUILD_FAILED");
  }
  if (mode === "definitive") {
    throw new Error(`Rejected transaction ${txId}: failed to verify the signature script: script ran, but verification failed (TEST INJECTION)`);
  }
  throw new Error("websocket connection dropped before response (TEST INJECTION)");
}

function fail(message, code) {
  const error = new Error(`wallet-requests-v2: ${message}`);
  if (code) error.code = code;
  return error;
}

function requestPath(config, requestId) {
  return path.join(config.dataRoot, "requests", `${requestId}.json`);
}

function saveRequest(config, request) {
  persistJsonDurably({ filePath: requestPath(config, request.requestId), value: request });
  return request;
}

function loadRequest(config, requestId) {
  const p = requestPath(config, requestId);
  if (!fs.existsSync(p)) {
    return null;
  }
  return readJsonStrict(p, "wallet request");
}

/* All durable request records for one vault, newest first (read-only). */
function listVaultRequests(config, vaultId) {
  const dir = path.join(config.dataRoot, "requests");
  if (!fs.existsSync(dir)) {
    return [];
  }
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    try {
      const r = readJsonStrict(path.join(dir, f), "wallet request");
      if (r.vaultId === vaultId) out.push(r);
    } catch {
      /* a corrupted request file fails loudly in its own flow, not here */
    }
  }
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

function utxoAmount(ref) {
  return BigInt((ref.utxoEntry ?? ref.entry ?? ref).amount ?? ref.amount);
}

async function findLiveCovenantRef(rpc, address, outpoint) {
  const resp = await rpc.getUtxosByAddresses({ addresses: [address] });
  return (
    (resp.entries ?? []).find((e) => {
      const o = e.outpoint ?? e.entry?.outpoint;
      return String(o.transactionId).toLowerCase() === outpoint.transactionId && Number(o.index) === outpoint.index;
    }) ?? null
  );
}

async function firstOrdinaryFuel(rpc, address, minimum) {
  const resp = await rpc.getUtxosByAddresses({ addresses: [address] });
  const refs = (resp.entries ?? []).filter((e) => (e.utxoEntry ?? e.entry ?? e).covenantId === undefined);
  const ref = refs.find((e) => utxoAmount(e) > minimum);
  if (!ref) {
    throw fail(`no ordinary UTXO above ${minimum} sompi at ${address} — fund it first`);
  }
  return ref;
}

function runEncoder({ sourcePath, constructorArgsPath, call }) {
  const callPath = path.join(os.tmpdir(), `pv2-wr-${crypto.randomUUID()}.json`);
  fs.writeFileSync(callPath, JSON.stringify({ ...call, contractVersion: CONTRACT_VERSION_V2 }), { mode: 0o600 });
  try {
    const r = spawnSync(ENCODER_PATH, [sourcePath, constructorArgsPath, callPath], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    if (r.status !== 0) {
      throw fail(`call encoding failed: ${r.stderr?.trim() ?? r.status}`);
    }
    const hex = r.stdout.trim();
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
      throw fail("call encoder returned invalid hex");
    }
    return hex;
  } finally {
    fs.unlinkSync(callPath);
  }
}

function extractSchnorr(signatureHex, label) {
  const bytes = Buffer.from(signatureHex, "hex");
  if (bytes.length === 66 && bytes[0] === 0x41) {
    return bytes.subarray(1);
  }
  if (bytes.length === 65) {
    return bytes;
  }
  throw fail(`${label} has unexpected length ${bytes.length}`, "SIGNATURE_INVALID");
}

function successorCallJson(state) {
  const j = stateToJson(state);
  return {
    protectedValue: j.protectedValue,
    periodStartDaa: j.periodStartDaa,
    periodSpent: j.periodSpent,
    paused: Number(j.paused),
    delegate: j.delegate,
    maxPerSpend: j.maxPerSpend,
    periodBudget: j.periodBudget,
    periodLengthDaa: j.periodLengthDaa,
    recipient1: j.recipients[0],
    recipient2: j.recipients[1],
    recipient3: j.recipients[2],
    delegateActive: Number(j.delegateActive),
    policyNonce: j.policyNonce
  };
}

/*
 * Resolve an action + params into: successor state, extra encoder call
 * fields, an optional payment output (pk,value), lock time, external owner
 * funding for the covenant output, the signer role, and a human-readable
 * review diff.
 */
function planTransition(state, action, params) {
  const before = stateToJson(state);
  switch (action) {
    case "delegateSpend": {
      const pay = BigInt(params.payAmountSompi);
      const idx = Number(params.recipientIndex);
      if (!Number.isInteger(idx) || idx < 1 || idx > 3) {
        throw fail("recipientIndex must be 1..3", "BUILD_FAILED");
      }
      const successor = spendSuccessorV2(state, pay);
      return {
        successor,
        role: "delegate",
        callExtra: { payAmount: pay.toString(), recipientIndex: idx },
        payment: { pk: state.recipients[idx - 1], value: pay },
        lockTime: 0n,
        externalFunding: 0n,
        review: {
          action,
          recipientIndex: idx,
          recipient: state.recipients[idx - 1],
          amountKas: sompiToKas(pay),
          protectedBeforeKas: sompiToKas(state.protectedValue),
          protectedAfterKas: sompiToKas(successor.protectedValue),
          periodSpentBeforeKas: sompiToKas(state.periodSpent),
          periodSpentAfterKas: sompiToKas(successor.periodSpent),
          remainingBudgetBeforeKas: sompiToKas(bmax(state.periodBudget - state.periodSpent)),
          remainingBudgetAfterKas: sompiToKas(bmax(successor.periodBudget - successor.periodSpent))
        }
      };
    }
    case "rolloverAndSpend": {
      const pay = BigInt(params.payAmountSompi);
      const idx = Number(params.recipientIndex);
      const periods = BigInt(params.periodsElapsed);
      const successor = rolloverSuccessorV2(state, pay, periods);
      return {
        successor,
        role: "delegate",
        callExtra: { payAmount: pay.toString(), recipientIndex: idx, periodsElapsed: periods.toString() },
        payment: { pk: state.recipients[idx - 1], value: pay },
        lockTime: successor.periodStartDaa,
        externalFunding: 0n,
        review: { action, recipientIndex: idx, amountKas: sompiToKas(pay), periodsElapsed: periods.toString(), newPeriodStartDaa: successor.periodStartDaa.toString() }
      };
    }
    case "ownerPause":
    case "ownerUnpause": {
      const successor = pauseSuccessorV2(state, action === "ownerPause");
      return { successor, role: "owner", callExtra: {}, payment: null, lockTime: 0n, externalFunding: 0n, review: { action, pausedBefore: before.paused === "1", pausedAfter: successor.paused === 1n } };
    }
    case "revokeDelegate": {
      const successor = revokeSuccessorV2(state);
      return { successor, role: "owner", callExtra: {}, payment: null, lockTime: 0n, externalFunding: 0n, review: { action, delegate: state.delegate, delegateActiveBefore: true, delegateActiveAfter: false } };
    }
    case "rotateDelegate": {
      const successor = rotateSuccessorV2(state, params.newDelegate);
      return {
        successor,
        role: "owner",
        callExtra: { newDelegate: successor.delegate },
        payment: null,
        lockTime: 0n,
        externalFunding: 0n,
        review: { action, oldDelegate: state.delegate, newDelegate: successor.delegate, periodSpentUnchangedKas: sompiToKas(state.periodSpent), periodStartDaaUnchanged: state.periodStartDaa.toString() }
      };
    }
    case "ownerTopUp": {
      const amount = BigInt(params.topUpAmountSompi);
      const successor = topUpSuccessorV2(state, amount);
      return {
        successor,
        role: "owner",
        callExtra: {},
        payment: null,
        lockTime: 0n,
        externalFunding: amount,
        review: { action, topUpKas: sompiToKas(amount), protectedBeforeKas: sompiToKas(state.protectedValue), protectedAfterKas: sompiToKas(successor.protectedValue), periodAccounting: "UNCHANGED", policy: "UNCHANGED" }
      };
    }
    case "migratePolicy": {
      const successor = migrateSuccessorV2(state, params.newPolicy ?? {});
      return {
        successor,
        role: "owner",
        callExtra: {},
        payment: null,
        lockTime: 0n,
        externalFunding: 0n,
        review: {
          action,
          policyNonceBefore: before.policyNonce,
          policyNonceAfter: successor.policyNonce.toString(),
          maxPerSpendBeforeKas: sompiToKas(state.maxPerSpend),
          maxPerSpendAfterKas: sompiToKas(successor.maxPerSpend),
          periodBudgetBeforeKas: sompiToKas(state.periodBudget),
          periodBudgetAfterKas: sompiToKas(successor.periodBudget),
          periodLengthBefore: state.periodLengthDaa.toString(),
          periodLengthAfter: successor.periodLengthDaa.toString(),
          recipientsBefore: [...state.recipients],
          recipientsAfter: [...successor.recipients],
          periodSpent: "UNCHANGED",
          periodStartDaa: "UNCHANGED"
        }
      };
    }
    case "ownerRecover": {
      /* Terminal path: the full protected value returns to the owner
       * wallet; no successor state exists. successor=state is value
       * bookkeeping only (expected recover value = protectedValue). */
      return {
        successor: state,
        role: "owner",
        callExtra: {},
        payment: null,
        lockTime: 0n,
        externalFunding: 0n,
        terminal: true,
        review: {
          action,
          recoveredKas: sompiToKas(state.protectedValue),
          terminal: "VAULT CLOSED — the full protected value returns to the owner wallet",
          protectedBeforeKas: sompiToKas(state.protectedValue),
          protectedAfterKas: "0"
        }
      };
    }
    default:
      throw fail(`unknown action ${action} — failing closed`, "BUILD_FAILED");
  }
}

function bmax(v) {
  return v > 0n ? v : 0n;
}

/*
 * BUILD stage. Returns the durable BUILT request (with unsigned Safe JSON,
 * signInputs, canonical review) that a signer will sign. No key, no
 * broadcast.
 */
async function buildWalletRequestV2({ config, vaultId, action, params = {}, signerAddress }) {
  const manifest = loadManifestV2(config, vaultId);
  if (!manifest) {
    throw fail(`no v0.2 manifest for vault ${vaultId}`, "BUILD_FAILED");
  }
  if (manifest.contractVersion !== CONTRACT_VERSION_V2) {
    throw fail(`unsupported contract version ${manifest.contractVersion}`, "BUILD_FAILED");
  }
  if (!manifest.live) {
    throw fail(`vault status is ${manifest.status} — no live state`, "BUILD_FAILED");
  }
  const template = manifest.template;
  const state = manifest.live.state;

  /*
   * Required ordering: exact state loaded (above) -> resolve action ->
   * AUTHORIZE the signer -> state prerequisites -> construction. An
   * unauthorized request must fail HERE, before any transaction building,
   * signature request, or durable claim.
   */
  const requiredRole = ROLE_BY_ACTION[action];
  if (!requiredRole) {
    throw fail(`unknown action ${action} — failing closed`, "BUILD_FAILED");
  }
  assertSignerAuthorized(config, { role: requiredRole, signerAddress, template, state, action });

  const plan = planTransition(state, action, params);
  if (plan.role !== requiredRole) {
    throw fail(`role map disagreement for ${action} — failing closed`, "BUILD_FAILED");
  }
  /* Delegate actions need an ACTIVE vault; owner lifecycle ops legitimately
   * target PAUSED vaults too (unpause/rotate/revoke/recover while paused). */
  if (plan.role === "delegate" && manifest.status !== VaultStatus.ACTIVE) {
    throw fail(`vault status is ${manifest.status} — delegate operations need ACTIVE`, "BUILD_FAILED");
  }
  const { successor, role, callExtra, payment, lockTime, externalFunding, terminal = false } = plan;

  const current = compileExactStateV2({ config, template, state });
  if (current.scriptSha256 !== manifest.live.scriptSha256) {
    throw fail("compiled current state != manifest script hash — failing closed", "STALE");
  }
  /* Terminal recovery has no successor state/script. */
  const next = terminal ? null : compileExactStateV2({ config, template, state: successor });
  const successorStateId = terminal ? null : computeStateIdV2({ networkId: config.networkId, template, state: successor });
  const currentAddress = covenantAddress(config, current.scriptBytes);
  const nextAddress = terminal ? null : covenantAddress(config, next.scriptBytes);

  const encoderPaths = {
    sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(current.buildDir, "constructor-args.json")
  };

  const { rpc, kaspa, serverInfo } = await connectVerified(config);
  try {
    const { Transaction, CovenantBinding, Hash, payToScriptHashScript, payToAddressScript } = kaspa;

    const covRef = await findLiveCovenantRef(rpc, currentAddress, manifest.live.outpoint);
    if (!covRef) {
      throw fail("manifest live outpoint not on chain — reconcile first", "STALE");
    }
    const covAmount = utxoAmount(covRef);
    if (covAmount !== state.protectedValue) {
      throw fail(`live outpoint value ${covAmount} != manifest ${state.protectedValue}`, "STALE");
    }
    const fuelRef = await firstOrdinaryFuel(rpc, signerAddress, FEE_PLACEHOLDER_SOMPI + externalFunding);
    const fuelAmount = utxoAmount(fuelRef);

    /* --- exact fee from KNOWN final sig-script lengths --- */
    // Covenant call length with a placeholder 65-byte signature.
    const placeholderCall = { function: action, signature: PLACEHOLDER_SIG_HEX, ...callExtra };
    if (action !== "ownerRecover") {
      placeholderCall.successor = successorCallJson(successor);
    }
    const callHex = runEncoder({ ...encoderPaths, call: placeholderCall });
    const covenantSigscriptHex = covenantSigscript(callHex, current.scriptBytes); // callHex + push + redeem
    const covenantSigLen = covenantSigscriptHex.length / 2;
    const fuelSigLen = 66; // 0x41 push + 65-byte sig

    // Assemble outputs (change starts as a placeholder, set after the fee).
    const outputs = [];
    if (payment) {
      outputs.push({ value: payment.value, scriptPublicKey: payToAddressScript(new kaspa.PublicKey(`02${payment.pk}`).toAddress(config.networkId).toString()) });
    }
    const successorIndex = outputs.length;
    if (terminal) {
      // ownerRecover: the full protected value pays out to the owner wallet.
      outputs.push({ value: state.protectedValue, scriptPublicKey: payToAddressScript(signerAddress) });
    } else {
      outputs.push({ value: successor.protectedValue, scriptPublicKey: payToScriptHashScript(next.scriptBytes.toString("hex")) });
    }
    const changeIndex = outputs.length;
    outputs.push({ value: 1n, scriptPublicKey: payToAddressScript(signerAddress) });

    // Build the unsigned transaction (inputs unsigned; wallet fills sigscripts).
    const txObject = {
      version: 1,
      inputs: [
        { previousOutpoint: { transactionId: manifest.live.outpoint.transactionId, index: manifest.live.outpoint.index }, signatureScript: "", sequence: 0n, sigOpCount: 0, computeBudget: V2_COVENANT_COMPUTE_BUDGET, utxo: covRef },
        { previousOutpoint: fuelRef.outpoint ?? fuelRef.entry?.outpoint, signatureScript: "", sequence: 0n, sigOpCount: 0, computeBudget: FEE_INPUT_COMPUTE_BUDGET, utxo: fuelRef }
      ],
      outputs,
      lockTime: BigInt(lockTime),
      subnetworkId: "0000000000000000000000000000000000000000",
      gas: 0n,
      payload: ""
    };
    const transaction = new Transaction(txObject);
    if (!terminal) {
      const outs = transaction.outputs;
      outs[successorIndex].covenant = new CovenantBinding(0, new Hash(manifest.live.covenantId));
      transaction.outputs = outs;
    }

    /*
     * Exact fee via the SAME descriptor implementation the headless path
     * uses (fee-mass.describeWasmTransaction), with the input signature
     * scripts overridden to their KNOWN final lengths (covenant call +
     * redeem push; 66-byte ordinary push). Then set the exact change.
     */
    const descriptor = describeWasmTransaction(transaction);
    descriptor.inputs[0].signatureScriptHex = "00".repeat(covenantSigLen);
    descriptor.inputs[1].signatureScriptHex = "00".repeat(fuelSigLen);
    const requiredFee = calculateRequiredFee(descriptor).minimumRequiredFee;

    const change = fuelAmount - requiredFee - externalFunding;
    if (change <= 0n) {
      throw fail(`fuel ${fuelAmount} cannot cover fee ${requiredFee} + funding ${externalFunding}`, "BUILD_FAILED");
    }
    const outs2 = transaction.outputs;
    outs2[changeIndex].value = change;
    transaction.outputs = outs2;

    const unsignedSafeJson = transaction.serializeToSafeJSON();

    const requestId = crypto.randomUUID();
    const request = saveRequest(config, {
      schema: REQUEST_SCHEMA,
      requestId,
      state: RequestState.BUILT,
      contractVersion: CONTRACT_VERSION_V2,
      networkId: config.networkId,
      vaultId,
      action,
      signerRole: role,
      signerAddress,
      predecessorOutpoint: manifest.live.outpoint,
      predecessorStateId: manifest.live.stateId,
      covenantId: manifest.live.covenantId,
      successorIndex,
      changeIndex,
      successorState: stateToJson(successor),
      successorStateId,
      successorAddress: nextAddress,
      successorScriptSha256: terminal ? null : next.scriptSha256,
      callExtra,
      encoderBuildDir: current.buildDir,
      requiredFeeSompi: requiredFee.toString(),
      review: { ...plan.review, feeKas: sompiToKas(requiredFee), feeSompi: requiredFee.toString(), network: config.networkId, signerRole: role, currentStateId: manifest.live.stateId },
      transaction: {
        unsignedSafeJson,
        signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }],
        covenantInputIndex: 0
      },
      serverNetwork: serverInfo.networkId,
      createdAt: new Date().toISOString()
    });
    return request;
  } finally {
    await rpc.disconnect();
  }
}

/*
 * BUILD stage for vault CREATION (genesis). The owner wallet funds and signs
 * ordinary p2pk inputs; there is no covenant input to re-embed. Returns a
 * durable BUILT request with kind "genesis".
 */
async function buildCreateWalletRequestV2({ config, templateInput, initialStateInput, signerAddress, delegateFuelSompi = "0", label = "" }) {
  const template = normalizeTemplateV2(templateInput);
  const state = normalizeStateV2(initialStateInput);
  // The connected wallet funds genesis AND is the vault owner: its
  // canonical identity must equal template.owner before anything is built.
  assertSignerAuthorized(config, { role: "owner", signerAddress, template, state, action: "createVault" });
  const compiled = compileExactStateV2({ config, template, state });
  const vaultAddress = covenantAddress(config, compiled.scriptBytes);
  const successorStateId = computeStateIdV2({ networkId: config.networkId, template, state });
  const fuel = BigInt(delegateFuelSompi);

  const { rpc, kaspa, serverInfo } = await connectVerified(config);
  try {
    const { ScriptBuilder, TransactionOutput, CovenantBinding, covenantId, createTransactions, payToScriptHashScript } = kaspa;

    const fundingResp = await rpc.getUtxosByAddresses({ addresses: [signerAddress] });
    const fundingEntries = (fundingResp.entries ?? []).filter((e) => (e.utxoEntry ?? e.entry ?? e).covenantId === undefined);
    if (!fundingEntries.length) {
      throw fail("owner address has no ordinary spendable UTXOs", "BUILD_FAILED");
    }

    const outputs = [{ address: vaultAddress, amount: state.protectedValue }];
    if (fuel > 0n) {
      const delegateAddress = new kaspa.PublicKey(`02${state.delegate}`).toAddress(config.networkId).toString();
      outputs.push({ address: delegateAddress, amount: fuel });
    }

    const generated = await createTransactions({ outputs, changeAddress: signerAddress, priorityFee: 100_000n, entries: fundingEntries, networkId: config.networkId });
    if (generated.transactions.length !== 1) {
      throw fail(`expected one funding transaction, generated ${generated.transactions.length}`, "BUILD_FAILED");
    }
    const transaction = generated.transactions[0].transaction;
    transaction.version = 1;

    const placeholder = new ScriptBuilder().addData(Buffer.alloc(66, 0x66)).drain();
    const inputs = transaction.inputs;
    for (let i = 0; i < inputs.length; i++) {
      inputs[i].sigOpCount = 0;
      inputs[i].computeBudget = FEE_INPUT_COMPUTE_BUDGET;
      inputs[i].signatureScript = placeholder;
    }
    transaction.inputs = inputs;

    const covenantSpk = payToScriptHashScript(compiled.scriptBytes.toString("hex"));
    const covenantSpkStr = covenantSpk.toString();
    const outputsNow = transaction.outputs;
    const vaultOutputIndex = outputsNow.findIndex((o) => o.scriptPublicKey.toString() === covenantSpkStr && BigInt(o.value) === state.protectedValue);
    if (vaultOutputIndex < 0) {
      throw fail("could not locate the covenant output", "BUILD_FAILED");
    }
    const unboundVaultOutput = new TransactionOutput(state.protectedValue, covenantSpk);
    const genesisCovenantId = covenantId(transaction.inputs[0].previousOutpoint, [{ index: vaultOutputIndex, output: unboundVaultOutput }]);
    const genesisCovenantIdHex = genesisCovenantId.toString().toLowerCase();

    const boundOutputs = transaction.outputs;
    boundOutputs[vaultOutputIndex].covenant = new CovenantBinding(0, genesisCovenantId);
    transaction.outputs = boundOutputs;

    // Clear placeholder sigs so the wallet fills them.
    const cleared = transaction.inputs;
    const signInputs = [];
    for (let i = 0; i < cleared.length; i++) {
      cleared[i].signatureScript = "";
      signInputs.push({ index: i, sighashType: 1 });
    }
    transaction.inputs = cleared;

    const unsignedSafeJson = transaction.serializeToSafeJSON();
    const requestId = crypto.randomUUID();
    const request = saveRequest(config, {
      schema: REQUEST_SCHEMA,
      requestId,
      kind: "genesis",
      state: RequestState.BUILT,
      contractVersion: CONTRACT_V2,
      networkId: config.networkId,
      vaultId: template.vaultId,
      action: "createVault",
      signerRole: "owner",
      signerAddress,
      label,
      template: { owner: template.owner, vaultId: template.vaultId },
      initialState: stateToJson(state),
      successorStateId,
      vaultAddress,
      vaultOutputIndex,
      covenantId: genesisCovenantIdHex,
      scriptSha256: compiled.scriptSha256,
      review: {
        action: "createVault",
        depositKas: sompiToKas(state.protectedValue),
        delegate: state.delegate,
        maxPerSpendKas: sompiToKas(state.maxPerSpend),
        periodBudgetKas: sompiToKas(state.periodBudget),
        periodLengthDaa: state.periodLengthDaa.toString(),
        recipients: [...state.recipients],
        network: config.networkId,
        signerRole: "owner"
      },
      transaction: { unsignedSafeJson, signInputs, covenantInputIndex: null },
      serverNetwork: serverInfo.networkId,
      createdAt: new Date().toISOString()
    });
    return request;
  } finally {
    await rpc.disconnect();
  }
}

async function attachCreateSignatureV2({ config, request, signedSafeJson }) {
  const { rpc, kaspa, serverInfo } = await connectVerified(config);
  try {
    const { Transaction, updateTransactionMass } = kaspa;
    const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
    let signed;
    try {
      signed = JSON.parse(signedSafeJson);
    } catch {
      request.state = RequestState.SIGNATURE_INVALID;
      saveRequest(config, request);
      throw fail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
    }
    assertPackageImmutable(unsigned, signed);

    const transaction = Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
    const ins = transaction.inputs;
    for (let i = 0; i < ins.length; i++) {
      const sig = signed.inputs[i]?.signatureScript;
      if (!sig) {
        request.state = RequestState.WALLET_REJECTED;
        saveRequest(config, request);
        throw fail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
      }
      ins[i].signatureScript = sig;
    }
    transaction.inputs = ins;

    request.state = RequestState.FINALIZED;
    saveRequest(config, request);

    if (!updateTransactionMass(config.networkId, transaction, 1)) {
      request.state = RequestState.PREFLIGHT_FAILED;
      saveRequest(config, request);
      throw fail("funding transaction exceeds the mass limit", "PREFLIGHT_FAILED");
    }
    const txId = transaction.finalize().toString().toLowerCase();
    if (serverInfo.networkId !== config.networkId) {
      request.state = RequestState.PREFLIGHT_FAILED;
      saveRequest(config, request);
      throw fail("network drift at preflight", "PREFLIGHT_FAILED");
    }

    claimSubmission(config, { txId, vaultId: request.vaultId, action: "createVault" });
    request.state = RequestState.SUBMITTING;
    request.txId = txId;
    saveRequest(config, request);

    let submitted;
    try {
      maybeInjectSubmitError(config, txId);
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      if (isDefinitiveSubmitRejection(message)) {
        // Genesis has no transition claim; release the submission claim so
        // nothing durable outlives a definitively rejected funding tx.
        releaseSubmissionClaim(config, txId);
        request.state = RequestState.SUBMISSION_REJECTED;
        saveRequest(config, request);
        throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
      }
      request.state = RequestState.RECONCILIATION_REQUIRED;
      saveRequest(config, request);
      throw fail(`submit failed: ${message} — reconcile required`, "RECONCILIATION_REQUIRED");
    }
    if (String(submitted.transactionId ?? submitted).toLowerCase() !== txId) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      saveRequest(config, request);
      throw fail("node returned an unexpected txid — reconcile required", "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    saveRequest(config, request);

    let proof = null;
    for (let i = 0; i < 30 && !proof; i++) {
      const utxos = await getAddressUtxos(rpc, request.vaultAddress);
      proof = utxos.find((u) => u.outpoint.transactionId === txId && u.outpoint.index === request.vaultOutputIndex && u.amount === BigInt(request.initialState.protectedValue) && u.covenantId === request.covenantId) ?? null;
      if (!proof) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!proof) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      saveRequest(config, request);
      throw fail(`submitted ${txId} but covenant outpoint not observed`, "RECONCILIATION_REQUIRED");
    }

    persistManifestV2(config, {
      schema: MANIFEST_SCHEMA_V2,
      contractVersion: CONTRACT_V2,
      networkId: config.networkId,
      vaultId: request.vaultId,
      label: request.label,
      status: VaultStatus.ACTIVE,
      template: request.template,
      live: {
        state: request.initialState,
        stateId: request.successorStateId,
        outpoint: { transactionId: txId, index: request.vaultOutputIndex },
        outpointValue: request.initialState.protectedValue,
        scriptSha256: request.scriptSha256,
        covenantId: request.covenantId
      },
      creationTxId: txId,
      latestTransitionTxId: null,
      lastTransition: null
    });
    persistReceipt(config, { txId, vaultId: request.vaultId, action: "createVault", proof: { requestId: request.requestId, outpoint: `${txId}:${request.vaultOutputIndex}`, covenantId: request.covenantId } });
    appendAudit(config, { vaultId: request.vaultId, action: "vault_created", actor: "owner", contractVersion: CONTRACT_V2, txId, result: "CHAIN_VERIFIED", newStateId: request.successorStateId, via: "wallet" });

    request.state = RequestState.CHAIN_VERIFIED;
    saveRequest(config, request);
    return request;
  } finally {
    await rpc.disconnect();
  }
}

/*
 * Assert the signed transaction differs from the unsigned one ONLY in the
 * input signature scripts (immutability of every consensus-visible field the
 * wallet must not alter).
 */
function assertPackageImmutable(unsigned, signed) {
  const strip = (tx) => ({
    version: tx.version,
    lockTime: tx.lockTime,
    subnetworkId: tx.subnetworkId,
    gas: tx.gas,
    payload: tx.payload,
    inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })),
    outputs: tx.outputs
  });
  const a = JSON.stringify(strip(unsigned));
  const b = JSON.stringify(strip(signed));
  if (a !== b) {
    throw fail("signed package mutated a consensus-visible field", "SIGNATURE_INVALID");
  }
}

/*
 * FINALIZE + SUBMIT stage. Accepts wallet-produced signed Safe JSON,
 * validates immutability, re-embeds the covenant signature, re-verifies the
 * exact fee, claims, submits, proves the exact successor, advances the
 * manifest. Returns the updated request.
 */
async function attachWalletSignatureV2({ config, requestId, signedSafeJson }) {
  const request = loadRequest(config, requestId);
  if (!request) {
    throw fail(`no request ${requestId}`, "BUILD_FAILED");
  }
  if (request.state !== RequestState.BUILT) {
    throw fail(`request ${requestId} is ${request.state}, not BUILT`, request.state);
  }

  if (request.kind === "genesis") {
    return attachCreateSignatureV2({ config, request, signedSafeJson });
  }

  const manifest = loadManifestV2(config, request.vaultId);
  if (!manifest || !manifest.live || manifest.live.stateId !== request.predecessorStateId) {
    request.state = RequestState.STALE;
    saveRequest(config, request);
    throw fail("vault advanced since this request was built — rebuild required", "STALE");
  }

  // Re-verify signer authorization against the CURRENT manifest before the
  // durable claim boundary (defense in depth; BUILD already enforced it).
  try {
    assertSignerAuthorized(config, {
      role: request.signerRole,
      signerAddress: request.signerAddress,
      template: manifest.template,
      state: manifest.live.state,
      action: request.action
    });
  } catch (e) {
    request.state = RequestState.AUTHORIZATION_FAILED;
    request.error = e.message;
    saveRequest(config, request);
    throw e;
  }

  const { rpc, kaspa, serverInfo } = await connectVerified(config);
  try {
    const { Transaction } = kaspa;
    const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
    let signed;
    try {
      signed = JSON.parse(signedSafeJson);
    } catch {
      request.state = RequestState.SIGNATURE_INVALID;
      saveRequest(config, request);
      throw fail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
    }
    assertPackageImmutable(unsigned, signed);

    // Covenant signature comes from input 0's returned signature script.
    const rawCovenant = signed.inputs[0]?.signatureScript;
    if (!rawCovenant) {
      request.state = RequestState.WALLET_REJECTED;
      saveRequest(config, request);
      throw fail("wallet did not sign the covenant input", "WALLET_REJECTED");
    }
    const covenantSig = extractSchnorr(rawCovenant, "covenant signature");

    // Terminal recovery carries no successor in the covenant call.
    const call = request.action === "ownerRecover"
      ? { function: "ownerRecover", signature: Buffer.from(covenantSig).toString("hex") }
      : { function: request.action, successor: successorCallJsonFromStored(request.successorState), signature: Buffer.from(covenantSig).toString("hex"), ...request.callExtra };
    const callHex = runEncoder({
      sourcePath: path.join(request.encoderBuildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(request.encoderBuildDir, "constructor-args.json"),
      call
    });

    // Reconstruct the final transaction from the unsigned one; input 0 gets
    // the covenant call, input 1 keeps the wallet's ordinary signature.
    const transaction = Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
    const current = compileExactStateV2({ config, template: manifest.template, state: manifest.live.state });
    const ins = transaction.inputs;
    ins[0].signatureScript = covenantSigscript(callHex, current.scriptBytes);
    ins[1].signatureScript = signed.inputs[1].signatureScript;
    transaction.inputs = ins;

    request.state = RequestState.FINALIZED;
    saveRequest(config, request);

    const txId = transaction.finalize().toString().toLowerCase();

    // Preflight: exact structure + network + version.
    if (serverInfo.networkId !== config.networkId || serverInfo.networkId !== request.networkId) {
      request.state = RequestState.PREFLIGHT_FAILED;
      saveRequest(config, request);
      throw fail("network drift at preflight", "PREFLIGHT_FAILED");
    }

    const expected = request.action === "ownerRecover"
      ? { kind: "recover", txId, index: 0, valueSompi: request.successorState.protectedValue, ownerAddress: request.signerAddress, contractVersion: CONTRACT_VERSION_V2 }
      : {
          kind: "successor",
          txId,
          index: request.successorIndex,
          valueSompi: request.successorState.protectedValue,
          covenantId: request.covenantId,
          scriptSha256: request.successorScriptSha256,
          stateId: request.successorStateId,
          address: request.successorAddress,
          state: request.successorState,
          action: request.action,
          contractVersion: CONTRACT_VERSION_V2
        };

    try {
      claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected });
    } catch (e) {
      request.state = RequestState.CLAIM_CONFLICT;
      request.error = e.message;
      saveRequest(config, request);
      throw e;
    }
    claimSubmission(config, { txId, vaultId: request.vaultId, action: request.action });

    request.state = RequestState.SUBMITTING;
    request.txId = txId;
    saveRequest(config, request);

    let submitted;
    try {
      maybeInjectSubmitError(config, txId);
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      /*
       * Classify the submission outcome. DEFINITIVE node rejection: the
       * transaction can never become a successor — confirm from chain
       * evidence that the predecessor is untouched and the expected effect
       * absent, then release BOTH claims so the vault is immediately
       * usable (motivating incident: stranded ownerTopUp claim
       * 12ffe0c2…). Anything ambiguous (transport failure, timeout)
       * KEEPS the claims and requires reconciliation — uncertainty never
       * releases a claim.
       */
      if (isDefinitiveSubmitRejection(message)) {
        const stillLive = await findLiveCovenantRef(rpc, covenantAddress(config, current.scriptBytes), request.predecessorOutpoint).catch(() => null);
        const effect = await proveExpectedEffect(rpc, { expected }).catch(() => "UNPROVEN");
        if (stillLive && !effect) {
          releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId });
          releaseSubmissionClaim(config, txId);
          appendAudit(config, {
            vaultId: request.vaultId,
            action: "submission_rejected_claims_released",
            actor: "system",
            txId,
            result: "REJECTED_BY_NODE",
            oldStateId: request.predecessorStateId,
            detail: message
          });
          request.state = RequestState.SUBMISSION_REJECTED;
          saveRequest(config, request);
          throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
        }
      }
      request.state = RequestState.RECONCILIATION_REQUIRED;
      saveRequest(config, request);
      throw fail(`submit failed: ${message} — claims kept, reconcile required`, "RECONCILIATION_REQUIRED");
    }
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      // The node acknowledged SOMETHING — ambiguous. Keep claims.
      request.state = RequestState.RECONCILIATION_REQUIRED;
      saveRequest(config, request);
      throw fail(`node returned ${returnedTxId}, expected ${txId} — reconcile required`, "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    saveRequest(config, request);

    // Chain proof (exact successor / recovery payout).
    const proof = await pollForProof(config, rpc, request, expected);
    if (!proof) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      saveRequest(config, request);
      throw fail(`submitted ${txId} but exact effect not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }

    advanceManifest(config, manifest, request, expected);
    request.state = RequestState.CHAIN_VERIFIED;
    saveRequest(config, request);

    persistReceipt(config, {
      txId,
      vaultId: request.vaultId,
      action: request.action,
      proof: { requestId, successorOutpoint: `${txId}:${expected.index}`, value: expected.valueSompi, requiredFeeSompi: request.requiredFeeSompi, actualFeeSompi: request.requiredFeeSompi }
    });
    appendAudit(config, {
      vaultId: request.vaultId,
      action: request.action,
      actor: request.signerRole,
      contractVersion: CONTRACT_VERSION_V2,
      txId,
      result: "CHAIN_VERIFIED",
      feeSompi: request.requiredFeeSompi,
      oldStateId: request.predecessorStateId,
      newStateId: expected.kind === "successor" ? expected.stateId : null,
      via: "wallet"
    });

    return request;
  } finally {
    await rpc.disconnect();
  }
}

function successorCallJsonFromStored(s) {
  return {
    protectedValue: s.protectedValue,
    periodStartDaa: s.periodStartDaa,
    periodSpent: s.periodSpent,
    paused: Number(s.paused),
    delegate: s.delegate,
    maxPerSpend: s.maxPerSpend,
    periodBudget: s.periodBudget,
    periodLengthDaa: s.periodLengthDaa,
    recipient1: s.recipients[0],
    recipient2: s.recipients[1],
    recipient3: s.recipients[2],
    delegateActive: Number(s.delegateActive),
    policyNonce: s.policyNonce
  };
}

async function pollForProof(config, rpc, request, expected, { attempts = 30, delayMs = 2000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const resp = await rpc.getUtxosByAddresses({ addresses: [expected.kind === "recover" ? expected.ownerAddress : expected.address] });
    const found = (resp.entries ?? []).find((e) => {
      const o = e.outpoint ?? e.entry?.outpoint;
      const u = e.utxoEntry ?? e.entry ?? e;
      if (String(o.transactionId).toLowerCase() !== expected.txId || Number(o.index) !== Number(expected.index)) return false;
      if (BigInt(u.amount) !== BigInt(expected.valueSompi)) return false;
      if (expected.kind === "successor") return String(u.covenantId).toLowerCase() === String(expected.covenantId).toLowerCase();
      return u.covenantId === undefined || u.covenantId === null;
    });
    if (found) return found;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return null;
}

function advanceManifest(config, manifest, request, expected) {
  if (expected.kind === "recover") {
    persistManifestV2(config, {
      ...manifest,
      status: VaultStatus.RECOVERED,
      template: { owner: manifest.template.owner, vaultId: manifest.template.vaultId },
      live: null,
      creationTxId: manifest.creationTxId,
      latestTransitionTxId: expected.txId,
      lastTransition: { action: "ownerRecover", txId: expected.txId, oldStateId: request.predecessorStateId, newStateId: null, oldOutpoint: request.predecessorOutpoint, newOutpoint: null }
    });
    return;
  }
  persistManifestV2(config, {
    ...manifest,
    status: Number(request.successorState.paused) === 1 ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
    template: { owner: manifest.template.owner, vaultId: manifest.template.vaultId },
    live: {
      state: request.successorState,
      stateId: expected.stateId,
      outpoint: { transactionId: expected.txId, index: expected.index },
      outpointValue: expected.valueSompi,
      scriptSha256: expected.scriptSha256,
      covenantId: expected.covenantId
    },
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: expected.txId,
    lastTransition: { action: request.action, txId: expected.txId, oldStateId: request.predecessorStateId, newStateId: expected.stateId, oldOutpoint: request.predecessorOutpoint, newOutpoint: { transactionId: expected.txId, index: expected.index } }
  });
}

function markWalletRejected(config, requestId) {
  const request = loadRequest(config, requestId);
  if (request && request.state === RequestState.BUILT) {
    request.state = RequestState.WALLET_REJECTED;
    saveRequest(config, request);
  }
  return request;
}

module.exports = {
  RequestState,
  ROLE_BY_ACTION,
  buildWalletRequestV2,
  buildCreateWalletRequestV2,
  attachWalletSignatureV2,
  markWalletRejected,
  loadRequest,
  listVaultRequests,
  requestPath,
  assertSignerAuthorized,
  isDefinitiveSubmitRejection
};
