"use strict";

/*
 * PolicyVault v0.2 vault operations: create, delegate spend/rollover, all
 * owner lifecycle transitions (pause/unpause/revoke/rotate/top-up/policy
 * migration) and terminal recovery.
 *
 * Same funds-safety discipline as the TESTNET-VERIFIED v0.1 modules:
 * exact live-state compilation, durable transition + submission claims
 * before broadcast, exact source-backed fees (fee-mass.js), chain proof
 * before any manifest advancement, audit events on every operation.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const {
  CONTRACT_VERSION_V2,
  normalizeTemplateV2,
  normalizeStateV2,
  computeStateIdV2,
  spendSuccessorV2,
  rolloverSuccessorV2,
  pauseSuccessorV2,
  revokeSuccessorV2,
  rotateSuccessorV2,
  topUpSuccessorV2,
  migrateSuccessorV2,
  stateToJson
} = require("./vault-state-v2");
const { compileExactStateV2 } = require("./contract-compiler-v2");
const { covenantAddress, connectVerified, getAddressUtxos } = require("./chain");
const { claimTransition, claimSubmission, persistReceipt } = require("./submission-claim");
const { VaultStatus } = require("./manifest");
const { MANIFEST_SCHEMA_V2, loadManifestV2, persistManifestV2 } = require("./manifest-v2");
const { covenantSigscript } = require("./spend-vault");
const { appendAudit } = require("./audit");
const { finalizeWithExactFee } = require("./fee-mass");

const ENCODER_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder");

/*
 * Compute budgets. The v0.2 covenant paths consume ~32K script units on the
 * real VM (tests/vm/tests/v2_compute_budget.rs); 1 budget unit = 10,000
 * script units, so 20 gives >6x headroom while costing 8,000 grams less
 * than v0.1's 100. Ordinary p2pk inputs keep the live-proven 10.
 */
const V2_COVENANT_COMPUTE_BUDGET = 20;
const FEE_INPUT_COMPUTE_BUDGET = 10;
const RELAY_MARGIN_SOMPI = 0n;
const FEE_PLACEHOLDER_SOMPI = 5_000_000n;

function fail(message) {
  throw new Error(`vault-ops-v2: ${message}`);
}

/*
 * TEST-ONLY deterministic crash injection for the live crash matrix
 * (mission §55). When the named env var is set, throws a recognizable
 * error at that pipeline point, leaving the durable state exactly as a
 * real crash would. Refuses to arm outside testnet.
 */
function maybeCrash(envName, context) {
  if (!process.env[envName]) {
    return;
  }
  if (process.env.KASPA_NETWORK_ID === "mainnet") {
    fail("crash injection must never be armed on mainnet");
  }
  const error = new Error(`INJECTED_CRASH:${envName}:${context.action}:${context.txId}`);
  error.injectedCrash = envName;
  throw error;
}

function runEncoderV2({ sourcePath, constructorArgsPath, call }) {
  if (!fs.existsSync(ENCODER_PATH)) {
    fail(`pv_call_encoder not built: ${ENCODER_PATH}`);
  }
  const callPath = path.join(os.tmpdir(), `pv2-call-${process.pid}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(callPath, JSON.stringify({ ...call, contractVersion: CONTRACT_VERSION_V2 }), { mode: 0o600 });
  try {
    const result = spawnSync(ENCODER_PATH, [sourcePath, constructorArgsPath, callPath], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024
    });
    if (result.status !== 0) {
      fail(`call encoding failed: ${result.stderr?.trim() ?? result.status}`);
    }
    const hex = result.stdout.trim();
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
      fail("call encoder returned invalid hex");
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
  fail(`${label} has unexpected length ${bytes.length}`);
}

function successorCallJson(state) {
  const json = stateToJson(state);
  return {
    protectedValue: json.protectedValue,
    periodStartDaa: json.periodStartDaa,
    periodSpent: json.periodSpent,
    paused: Number(json.paused),
    delegate: json.delegate,
    maxPerSpend: json.maxPerSpend,
    periodBudget: json.periodBudget,
    periodLengthDaa: json.periodLengthDaa,
    recipient1: json.recipients[0],
    recipient2: json.recipients[1],
    recipient3: json.recipients[2],
    delegateActive: Number(json.delegateActive),
    policyNonce: json.policyNonce
  };
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
    fail(`no ordinary UTXO above ${minimum} sompi at ${address} — fund it first`);
  }
  return ref;
}

async function pollForProof(fn, { attempts = 30, delayMs = 2_000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const result = await fn();
    if (result) {
      return result;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return null;
}

/* ------------------------------------------------------------- creation */

async function createVaultV2({ config, templateInput, initialStateInput, fundingKey, delegateFuelSompi = 0n, label = "" }) {
  const template = normalizeTemplateV2(templateInput);
  const state = normalizeStateV2(initialStateInput);
  const stateId = computeStateIdV2({ networkId: config.networkId, template, state });
  const compiled = compileExactStateV2({ config, template, state });
  const vaultAddress = covenantAddress(config, compiled.scriptBytes);

  const { rpc, kaspa, serverInfo } = await connectVerified(config);
  try {
    const {
      ScriptBuilder,
      TransactionOutput,
      CovenantBinding,
      covenantId,
      createTransactions,
      createInputSignature,
      PrivateKey,
      payToScriptHashScript,
      updateTransactionMass
    } = kaspa;

    const fundingPrivate = new PrivateKey(fundingKey.secret);
    const fundingAddress = fundingKey.address;

    const fundingEntriesRaw = await rpc.getUtxosByAddresses({ addresses: [fundingAddress] });
    const fundingEntries = (fundingEntriesRaw.entries ?? []).filter(
      (entry) => (entry.utxoEntry ?? entry.entry ?? entry).covenantId === undefined
    );
    if (fundingEntries.length === 0) {
      fail("funding address has no ordinary spendable UTXOs");
    }

    const outputs = [{ address: vaultAddress, amount: state.protectedValue }];
    if (delegateFuelSompi > 0n) {
      const delegateAddress = new kaspa.PublicKey(`02${state.delegate}`).toAddress(config.networkId).toString();
      outputs.push({ address: delegateAddress, amount: delegateFuelSompi });
    }

    const generated = await createTransactions({
      outputs,
      changeAddress: fundingAddress,
      priorityFee: 100_000n, // UTXO-selection headroom only; exact fee set below
      entries: fundingEntries,
      networkId: config.networkId
    });
    if (generated.transactions.length !== 1) {
      fail(`expected one funding transaction, generated ${generated.transactions.length}`);
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
    const vaultOutputIndex = outputsNow.findIndex(
      (o) => o.scriptPublicKey.toString() === covenantSpkStr && BigInt(o.value) === state.protectedValue
    );
    if (vaultOutputIndex < 0) {
      fail("could not locate the covenant output");
    }
    const changeIndex = outputsNow.findIndex(
      (o, i) =>
        i !== vaultOutputIndex &&
        o.scriptPublicKey.toString() !== covenantSpkStr &&
        (delegateFuelSompi === 0n || BigInt(o.value) !== delegateFuelSompi)
    );
    if (changeIndex < 0) {
      fail("could not locate the change output — funding UTXOs too close to the vault amount");
    }

    const unboundVaultOutput = new TransactionOutput(state.protectedValue, covenantSpk);
    const genesisCovenantId = covenantId(transaction.inputs[0].previousOutpoint, [
      { index: vaultOutputIndex, output: unboundVaultOutput }
    ]);
    const genesisCovenantIdHex = genesisCovenantId.toString().toLowerCase();

    const boundOutputs = transaction.outputs;
    boundOutputs[vaultOutputIndex].covenant = new CovenantBinding(0, genesisCovenantId);
    transaction.outputs = boundOutputs;

    const totalInput = transaction.inputs.reduce((s, input) => s + BigInt(input.utxo.amount), 0n);
    function signAll(tx) {
      const cleared = tx.inputs;
      for (let i = 0; i < cleared.length; i++) {
        cleared[i].signatureScript = "";
      }
      tx.inputs = cleared;
      for (let i = 0; i < tx.inputs.length; i++) {
        const signature = createInputSignature(tx, i, fundingPrivate);
        const resigned = tx.inputs;
        resigned[i].signatureScript = signature;
        tx.inputs = resigned;
      }
      return tx;
    }

    const feeResult = finalizeWithExactFee({
      transaction,
      signAll,
      changeIndex,
      totalInputValue: totalInput,
      relayMargin: RELAY_MARGIN_SOMPI
    });

    if (!updateTransactionMass(config.networkId, transaction, 1)) {
      fail("funding transaction exceeds the mass limit");
    }
    const txId = transaction.finalize().toString().toLowerCase();

    if (BigInt(transaction.outputs[vaultOutputIndex].value) !== state.protectedValue) {
      fail("preflight: covenant output value drifted");
    }
    if (serverInfo.networkId !== config.networkId) {
      fail("preflight: network drifted");
    }

    await claimSubmission(config, { txId, vaultId: template.vaultId, action: "createVaultV2" });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      fail(`node returned txid ${returnedTxId}, expected ${txId} — refusing to proceed`);
    }

    const proof = await pollForProof(async () => {
      const utxos = await getAddressUtxos(rpc, vaultAddress);
      return (
        utxos.find(
          (u) =>
            u.outpoint.transactionId === txId &&
            u.outpoint.index === vaultOutputIndex &&
            u.amount === state.protectedValue &&
            u.covenantId === genesisCovenantIdHex
        ) ?? null
      );
    });
    if (!proof) {
      fail(`submitted ${txId} but the covenant outpoint was not observed — claim preserved; reconcile before any retry`);
    }

    const manifest = await persistManifestV2(config, {
      schema: MANIFEST_SCHEMA_V2,
      contractVersion: CONTRACT_VERSION_V2,
      networkId: config.networkId,
      vaultId: template.vaultId,
      label,
      status: VaultStatus.ACTIVE,
      template: { owner: template.owner, vaultId: template.vaultId },
      live: {
        state: stateToJson(state),
        stateId,
        outpoint: { transactionId: txId, index: vaultOutputIndex },
        outpointValue: state.protectedValue.toString(),
        scriptSha256: compiled.scriptSha256,
        covenantId: genesisCovenantIdHex
      },
      creationTxId: txId,
      latestTransitionTxId: null,
      lastTransition: null
    });

    await persistReceipt(config, {
      txId,
      vaultId: template.vaultId,
      action: "createVaultV2",
      proof: {
        outpoint: proof.outpoint,
        amount: proof.amount.toString(),
        covenantId: proof.covenantId,
        requiredFeeSompi: feeResult.requiredFee.toString(),
        actualFeeSompi: feeResult.actualFee.toString()
      }
    });

    await appendAudit(config, {
      vaultId: template.vaultId,
      action: "vault_created",
      actor: "owner",
      contractVersion: CONTRACT_VERSION_V2,
      txId,
      result: "CHAIN_VERIFIED",
      feeSompi: feeResult.actualFee.toString(),
      newStateId: stateId
    });

    return { txId, vaultAddress, vaultOutputIndex, covenantId: genesisCovenantIdHex, stateId, manifest, fee: feeResult };
  } finally {
    await rpc.disconnect();
  }
}

/* --------------------------------------------- shared covenant transition */

/*
 * Execute one same-template covenant transition (spend or owner lifecycle).
 * The successor output sits at `successorIndex` in `outputsSpec`;
 * `changeIndex` is the ordinary change output absorbing the exact fee.
 */
async function executeTransitionV2({
  config,
  manifest,
  action,
  successor,
  signerKey,
  callExtra = {},
  paymentOutput = null,
  lockTime = 0n,
  externalFundingSompi = 0n,
  auditAction,
  auditActor,
  auditExtra = {}
}) {
  const template = manifest.template;
  const state = manifest.live.state;
  const vaultId = manifest.vaultId;

  const current = compileExactStateV2({ config, template, state });
  if (current.scriptSha256 !== manifest.live.scriptSha256) {
    fail("compiled current state does not match the manifest script hash — failing closed");
  }
  const next = compileExactStateV2({ config, template, state: successor });
  const successorStateId = computeStateIdV2({ networkId: config.networkId, template, state: successor });
  const currentAddress = covenantAddress(config, current.scriptBytes);
  const nextAddress = covenantAddress(config, next.scriptBytes);

  const { rpc, kaspa } = await connectVerified(config);
  try {
    const { PrivateKey, Transaction, CovenantBinding, Hash, payToScriptHashScript, payToAddressScript, createInputSignature } =
      kaspa;

    const signerPrivate = new PrivateKey(signerKey.secret);

    const covRef = await findLiveCovenantRef(rpc, currentAddress, manifest.live.outpoint);
    if (!covRef) {
      fail("the manifest live outpoint is not on chain — reconcile before this operation");
    }
    const covAmount = utxoAmount(covRef);
    if (covAmount !== state.protectedValue) {
      fail(`live outpoint value ${covAmount} != manifest protectedValue ${state.protectedValue}`);
    }

    const fuelNeed = FEE_PLACEHOLDER_SOMPI + externalFundingSompi;
    const fuelRef = await firstOrdinaryFuel(rpc, signerKey.address, fuelNeed);
    const fuelAmount = utxoAmount(fuelRef);

    const outputs = [];
    if (paymentOutput) {
      outputs.push(paymentOutput(kaspa));
    }
    const successorIndex = outputs.length;
    outputs.push({
      value: successor.protectedValue,
      scriptPublicKey: payToScriptHashScript(next.scriptBytes.toString("hex"))
    });
    const changeIndex = outputs.length;
    outputs.push({
      value: fuelAmount - FEE_PLACEHOLDER_SOMPI - externalFundingSompi,
      scriptPublicKey: payToAddressScript(signerKey.address)
    });

    const txObject = {
      version: 1,
      inputs: [
        {
          previousOutpoint: { transactionId: manifest.live.outpoint.transactionId, index: manifest.live.outpoint.index },
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: V2_COVENANT_COMPUTE_BUDGET,
          utxo: covRef
        },
        {
          previousOutpoint: fuelRef.outpoint ?? fuelRef.entry?.outpoint,
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: FEE_INPUT_COMPUTE_BUDGET,
          utxo: fuelRef
        }
      ],
      outputs,
      lockTime: BigInt(lockTime),
      subnetworkId: "0000000000000000000000000000000000000000",
      gas: 0n,
      payload: ""
    };

    const transaction = new Transaction(txObject);
    const outs = transaction.outputs;
    outs[successorIndex].covenant = new CovenantBinding(0, new Hash(manifest.live.covenantId));
    transaction.outputs = outs;

    const encoderPaths = {
      sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(current.buildDir, "constructor-args.json")
    };

    function signAll(tx) {
      const raw = createInputSignature(tx, 0, signerPrivate);
      const sig = extractSchnorr(raw, "covenant signature");
      const call = {
        function: action,
        successor: successorCallJson(successor),
        signature: Buffer.from(sig).toString("hex"),
        ...callExtra
      };
      const callHex = runEncoderV2({ ...encoderPaths, call });
      const ins = tx.inputs;
      ins[0].signatureScript = covenantSigscript(callHex, current.scriptBytes);
      tx.inputs = ins;
      const ins2 = tx.inputs;
      ins2[1].signatureScript = createInputSignature(tx, 1, signerPrivate);
      tx.inputs = ins2;
      return tx;
    }
    const feeResult = finalizeWithExactFee({
      transaction,
      signAll,
      changeIndex,
      totalInputValue: covAmount + fuelAmount,
      relayMargin: RELAY_MARGIN_SOMPI
    });

    if (feeResult.actualFee + externalFundingSompi > fuelAmount) {
      fail("fee + funding exceeds available fuel — refusing");
    }

    if (process.env.PV_DEBUG_DUMP) {
      fs.writeFileSync(
        path.join(process.env.PV_DEBUG_DUMP, `${action}-tx.json`),
        JSON.stringify(
          {
            action,
            tx: JSON.parse(transaction.serializeToSafeJSON()),
            utxos: [
              { covenantId: manifest.live.covenantId, amount: covAmount.toString(), scriptHex: current.scriptHex, isCovenant: true },
              { amount: fuelAmount.toString() }
            ],
            currentScriptHex: current.scriptHex,
            nextScriptHex: next.scriptHex
          },
          null,
          2
        )
      );
    }

    const txId = transaction.finalize().toString().toLowerCase();

    await claimTransition(config, {
      outpoint: manifest.live.outpoint,
      action,
      txId,
      vaultId,
      stateId: manifest.live.stateId,
      expected: {
        kind: "successor",
        txId,
        index: successorIndex,
        valueSompi: successor.protectedValue.toString(),
        covenantId: manifest.live.covenantId,
        scriptSha256: next.scriptSha256,
        stateId: successorStateId,
        address: nextAddress,
        state: stateToJson(successor),
        action,
        contractVersion: CONTRACT_VERSION_V2
      }
    });
    await claimSubmission(config, { txId, vaultId, action });

    /* TEST-ONLY crash injection (mission §55). Never set in production. */
    maybeCrash("PV_CRASH_AFTER_CLAIM", { action, txId });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      fail(`node returned txid ${returnedTxId}, expected ${txId}`);
    }

    maybeCrash("PV_CRASH_AFTER_SUBMIT", { action, txId });

    const proof = await pollForProof(async () => {
      const resp = await rpc.getUtxosByAddresses({ addresses: [nextAddress] });
      return (
        (resp.entries ?? []).find((e) => {
          const outpoint = e.outpoint ?? e.entry?.outpoint;
          const utxo = e.utxoEntry ?? e.entry ?? e;
          return (
            String(outpoint.transactionId).toLowerCase() === txId &&
            Number(outpoint.index) === successorIndex &&
            BigInt(utxo.amount) === successor.protectedValue &&
            String(utxo.covenantId).toLowerCase() === manifest.live.covenantId
          );
        }) ?? null
      );
    });
    if (!proof) {
      fail(`submitted ${txId} but the successor was not observed — claim preserved; reconcile before retrying`);
    }

    await persistManifestV2(config, {
      ...manifest,
      status: successor.paused === 1n ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
      template: { owner: template.owner, vaultId: template.vaultId },
      live: {
        state: stateToJson(successor),
        stateId: successorStateId,
        outpoint: { transactionId: txId, index: successorIndex },
        outpointValue: successor.protectedValue.toString(),
        scriptSha256: next.scriptSha256,
        covenantId: manifest.live.covenantId
      },
      creationTxId: manifest.creationTxId,
      latestTransitionTxId: txId,
      lastTransition: {
        action,
        txId,
        oldStateId: manifest.live.stateId,
        newStateId: successorStateId,
        oldOutpoint: manifest.live.outpoint,
        newOutpoint: { transactionId: txId, index: successorIndex }
      }
    });

    await persistReceipt(config, {
      txId,
      vaultId,
      action,
      proof: {
        successorOutpoint: `${txId}:${successorIndex}`,
        value: successor.protectedValue.toString(),
        requiredFeeSompi: feeResult.requiredFee.toString(),
        actualFeeSompi: feeResult.actualFee.toString()
      }
    });

    await appendAudit(config, {
      vaultId,
      action: auditAction,
      actor: auditActor,
      contractVersion: CONTRACT_VERSION_V2,
      txId,
      result: "CHAIN_VERIFIED",
      feeSompi: feeResult.actualFee.toString(),
      oldStateId: manifest.live.stateId,
      newStateId: successorStateId,
      ...auditExtra
    });

    return { txId, successor, successorStateId, successorOutpoint: `${txId}:${successorIndex}`, fee: feeResult };
  } finally {
    await rpc.disconnect();
  }
}

async function requireLiveV2(config, vaultId, allowPaused = true) {
  const manifest = await loadManifestV2(config, vaultId);
  if (!manifest) {
    fail(`no v0.2 manifest for vault ${vaultId}`);
  }
  if (!manifest.live) {
    fail(`vault ${vaultId} has no live state (status ${manifest.status})`);
  }
  if (!allowPaused && manifest.status !== VaultStatus.ACTIVE) {
    fail(`vault status is ${manifest.status} — refusing`);
  }
  return manifest;
}

/* ------------------------------------------------------------ operations */

async function spendFromVaultV2({ config, vaultId, delegateKey, payAmount, recipientIndex, periodsElapsed = 0 }) {
  const manifest = await requireLiveV2(config, vaultId, false);
  const state = manifest.live.state;
  const pay = BigInt(payAmount);
  const periods = BigInt(periodsElapsed ?? 0);
  const idx = Number(recipientIndex);
  if (!Number.isInteger(idx) || idx < 1 || idx > 3) {
    fail("recipientIndex must be 1..3");
  }

  const successor = periods >= 1n ? rolloverSuccessorV2(state, pay, periods) : spendSuccessorV2(state, pay);
  const recipientPk = state.recipients[idx - 1];

  let recipientAddress;
  const result = await executeTransitionV2({
    config,
    manifest,
    action: periods >= 1n ? "rolloverAndSpend" : "delegateSpend",
    successor,
    signerKey: delegateKey,
    callExtra:
      periods >= 1n
        ? { payAmount: pay.toString(), recipientIndex: idx, periodsElapsed: periods.toString() }
        : { payAmount: pay.toString(), recipientIndex: idx },
    paymentOutput: (kaspa) => {
      recipientAddress = new kaspa.PublicKey(`02${recipientPk}`).toAddress(config.networkId).toString();
      return { value: pay, scriptPublicKey: kaspa.payToAddressScript(recipientAddress) };
    },
    lockTime: periods >= 1n ? successor.periodStartDaa : 0n,
    auditAction: periods >= 1n ? "delegate_spend_rollover" : "delegate_spend",
    auditActor: "delegate",
    auditExtra: { amountSompi: pay.toString(), recipientIndex: idx }
  });
  return { ...result, recipientAddress };
}

async function setPausedV2({ config, vaultId, ownerKey, pause }) {
  const manifest = await requireLiveV2(config, vaultId);
  const successor = pauseSuccessorV2(manifest.live.state, pause);
  return executeTransitionV2({
    config,
    manifest,
    action: pause ? "ownerPause" : "ownerUnpause",
    successor,
    signerKey: ownerKey,
    auditAction: pause ? "vault_paused" : "vault_unpaused",
    auditActor: "owner"
  });
}

async function revokeDelegateV2({ config, vaultId, ownerKey }) {
  const manifest = await requireLiveV2(config, vaultId);
  const successor = revokeSuccessorV2(manifest.live.state);
  return executeTransitionV2({
    config,
    manifest,
    action: "revokeDelegate",
    successor,
    signerKey: ownerKey,
    auditAction: "delegate_revoked",
    auditActor: "owner"
  });
}

async function rotateDelegateV2({ config, vaultId, ownerKey, newDelegate }) {
  const manifest = await requireLiveV2(config, vaultId);
  const successor = rotateSuccessorV2(manifest.live.state, newDelegate);
  return executeTransitionV2({
    config,
    manifest,
    action: "rotateDelegate",
    successor,
    signerKey: ownerKey,
    callExtra: { newDelegate: successor.delegate },
    auditAction: "delegate_rotated",
    auditActor: "owner",
    auditExtra: { oldDelegate: manifest.live.state.delegate, newDelegate: successor.delegate }
  });
}

async function topUpVaultV2({ config, vaultId, ownerKey, topUpAmount }) {
  const manifest = await requireLiveV2(config, vaultId);
  const amount = BigInt(topUpAmount);
  const successor = topUpSuccessorV2(manifest.live.state, amount);
  return executeTransitionV2({
    config,
    manifest,
    action: "ownerTopUp",
    successor,
    signerKey: ownerKey,
    externalFundingSompi: amount,
    auditAction: "vault_topped_up",
    auditActor: "owner",
    auditExtra: { amountSompi: amount.toString() }
  });
}

async function migratePolicyV2({ config, vaultId, ownerKey, newPolicy }) {
  const manifest = await requireLiveV2(config, vaultId);
  const successor = migrateSuccessorV2(manifest.live.state, newPolicy ?? {});
  return executeTransitionV2({
    config,
    manifest,
    action: "migratePolicy",
    successor,
    signerKey: ownerKey,
    auditAction: "policy_migrated",
    auditActor: "owner",
    auditExtra: {
      policyNonce: successor.policyNonce.toString(),
      maxPerSpend: successor.maxPerSpend.toString(),
      periodBudget: successor.periodBudget.toString(),
      periodLengthDaa: successor.periodLengthDaa.toString()
    }
  });
}

async function recoverVaultV2({ config, vaultId, ownerKey }) {
  const manifest = await requireLiveV2(config, vaultId);
  const template = manifest.template;
  const state = manifest.live.state;

  const current = compileExactStateV2({ config, template, state });
  if (current.scriptSha256 !== manifest.live.scriptSha256) {
    fail("compiled current state does not match the manifest script hash — failing closed");
  }
  const currentAddress = covenantAddress(config, current.scriptBytes);

  const { rpc, kaspa } = await connectVerified(config);
  try {
    const { PrivateKey, Transaction, createInputSignature, payToAddressScript } = kaspa;
    const ownerPrivate = new PrivateKey(ownerKey.secret);

    const covRef = await findLiveCovenantRef(rpc, currentAddress, manifest.live.outpoint);
    if (!covRef) {
      fail("the manifest live outpoint is not on chain — reconcile before recovery");
    }
    const covAmount = utxoAmount(covRef);
    if (covAmount !== state.protectedValue) {
      fail(`live outpoint value ${covAmount} != manifest protectedValue ${state.protectedValue}`);
    }
    const fuelRef = await firstOrdinaryFuel(rpc, ownerKey.address, FEE_PLACEHOLDER_SOMPI);
    const fuelAmount = utxoAmount(fuelRef);

    const txObject = {
      version: 1,
      inputs: [
        {
          previousOutpoint: { transactionId: manifest.live.outpoint.transactionId, index: manifest.live.outpoint.index },
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: V2_COVENANT_COMPUTE_BUDGET,
          utxo: covRef
        },
        {
          previousOutpoint: fuelRef.outpoint ?? fuelRef.entry?.outpoint,
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: FEE_INPUT_COMPUTE_BUDGET,
          utxo: fuelRef
        }
      ],
      outputs: [
        { value: state.protectedValue, scriptPublicKey: payToAddressScript(ownerKey.address) },
        { value: fuelAmount - FEE_PLACEHOLDER_SOMPI, scriptPublicKey: payToAddressScript(ownerKey.address) }
      ],
      lockTime: 0n,
      subnetworkId: "0000000000000000000000000000000000000000",
      gas: 0n,
      payload: ""
    };

    const transaction = new Transaction(txObject);

    const encoderPaths = {
      sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(current.buildDir, "constructor-args.json")
    };
    function signAll(tx) {
      const sig = extractSchnorr(createInputSignature(tx, 0, ownerPrivate), "covenant signature");
      const callHex = runEncoderV2({
        ...encoderPaths,
        call: { function: "ownerRecover", signature: Buffer.from(sig).toString("hex") }
      });
      const ins = tx.inputs;
      ins[0].signatureScript = covenantSigscript(callHex, current.scriptBytes);
      tx.inputs = ins;
      const ins2 = tx.inputs;
      ins2[1].signatureScript = createInputSignature(tx, 1, ownerPrivate);
      tx.inputs = ins2;
      return tx;
    }

    const feeResult = finalizeWithExactFee({
      transaction,
      signAll,
      changeIndex: 1,
      totalInputValue: covAmount + fuelAmount,
      relayMargin: RELAY_MARGIN_SOMPI
    });

    const txId = transaction.finalize().toString().toLowerCase();

    await claimTransition(config, {
      outpoint: manifest.live.outpoint,
      action: "ownerRecover",
      txId,
      vaultId,
      stateId: manifest.live.stateId,
      expected: {
        kind: "recover",
        txId,
        index: 0,
        valueSompi: state.protectedValue.toString(),
        ownerAddress: ownerKey.address,
        contractVersion: CONTRACT_VERSION_V2
      }
    });
    await claimSubmission(config, { txId, vaultId, action: "ownerRecover" });

    maybeCrash("PV_CRASH_AFTER_CLAIM", { action: "ownerRecover", txId });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    maybeCrash("PV_CRASH_AFTER_SUBMIT", { action: "ownerRecover", txId });
    if (returnedTxId !== txId) {
      fail(`node returned txid ${returnedTxId}, expected ${txId}`);
    }

    /* Terminal proof: the old covenant outpoint must disappear AND the
     * owner P2PK output at :0 must appear. */
    const proof = await pollForProof(async () => {
      const gone = !(await findLiveCovenantRef(rpc, currentAddress, manifest.live.outpoint));
      return gone ? { consumed: true } : null;
    });
    if (!proof) {
      fail(`submitted ${txId} but the covenant outpoint is still live — claim preserved; reconcile before retrying`);
    }

    await persistManifestV2(config, {
      ...manifest,
      status: VaultStatus.RECOVERED,
      template: { owner: template.owner, vaultId: template.vaultId },
      live: null,
      creationTxId: manifest.creationTxId,
      latestTransitionTxId: txId,
      lastTransition: {
        action: "ownerRecover",
        txId,
        oldStateId: manifest.live.stateId,
        newStateId: null,
        oldOutpoint: manifest.live.outpoint,
        newOutpoint: null
      }
    });

    await persistReceipt(config, {
      txId,
      vaultId,
      action: "ownerRecover",
      proof: {
        consumedOutpoint: `${manifest.live.outpoint.transactionId}:${manifest.live.outpoint.index}`,
        recoveredValue: state.protectedValue.toString(),
        requiredFeeSompi: feeResult.requiredFee.toString(),
        actualFeeSompi: feeResult.actualFee.toString()
      }
    });

    await appendAudit(config, {
      vaultId,
      action: "vault_recovered",
      actor: "owner",
      contractVersion: CONTRACT_VERSION_V2,
      txId,
      result: "CHAIN_VERIFIED",
      amountSompi: state.protectedValue.toString(),
      feeSompi: feeResult.actualFee.toString(),
      oldStateId: manifest.live.stateId
    });

    return { txId, recoveredValue: state.protectedValue, fee: feeResult };
  } finally {
    await rpc.disconnect();
  }
}

module.exports = {
  CONTRACT_VERSION_V2,
  V2_COVENANT_COMPUTE_BUDGET,
  createVaultV2,
  spendFromVaultV2,
  setPausedV2,
  revokeDelegateV2,
  rotateDelegateV2,
  topUpVaultV2,
  migratePolicyV2,
  recoverVaultV2
};
