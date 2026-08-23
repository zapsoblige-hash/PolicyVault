"use strict";

/*
 * Delegate spend transition (delegateSpend / rolloverAndSpend).
 *
 * Transaction shape (docs/covenant-spec.md §6):
 *   INPUT 0  live covenant UTXO (covenant call sigscript)
 *   INPUT 1+ delegate ordinary fee UTXOs
 *   OUTPUT 0 payment to allowlisted recipient (exact payAmount)
 *   OUTPUT 1 successor covenant (exact new protectedValue, bound)
 *   OUTPUT 2 delegate change
 *
 * The covenant-call sigscript is produced by the Rust pv_call_encoder
 * (silverscript build_sig_script_for_covenant_decl) plus a manual
 * redeem-script push.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { compileExactState } = require("./contract-compiler");
const {
  normalizePolicy,
  normalizeState,
  computeStateId,
  spendSuccessor,
  rolloverSuccessor
} = require("./vault-state");
const { covenantAddress, connectVerified } = require("./chain");
const { claimTransition, claimSubmission, persistReceipt } = require("./submission-claim");
const { loadManifest, persistManifest, VaultStatus } = require("./manifest");
const { appendAudit } = require("./audit");
const { finalizeWithExactFee } = require("./fee-mass");

const ENCODER_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder");

const COVENANT_INPUT_COMPUTE_BUDGET = 100;
const FEE_INPUT_COMPUTE_BUDGET = 10;
/*
 * Optional relay margin added on top of the exact consensus-required fee
 * (source-backed, docs/fee-mass-spec.md). Taken only from ordinary delegate
 * fuel, never from protected principal. 0 = pay the exact minimum.
 */
const RELAY_MARGIN_SOMPI = 0n;
/* A placeholder change reservation used before the exact fee is computed. */
const FEE_PLACEHOLDER_SOMPI = 5_000_000n;

function fail(message) {
  throw new Error(`spend-vault: ${message}`);
}

function runEncoder({ sourcePath, constructorArgsPath, call }) {
  if (!fs.existsSync(ENCODER_PATH)) {
    fail(`pv_call_encoder not built: ${ENCODER_PATH}`);
  }
  const callPath = path.join(os.tmpdir(), `pv-call-${process.pid}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(callPath, JSON.stringify(call), { mode: 0o600 });
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

/* callHex + canonical push of the (255, 65535]-byte redeem script. */
function covenantSigscript(callHex, redeemScript) {
  const callBytes = Buffer.from(callHex, "hex");
  if (redeemScript.length <= 255 || redeemScript.length > 0xffff) {
    fail(`unexpected redeem script size ${redeemScript.length}`);
  }
  const push = Buffer.alloc(3);
  push[0] = 0x4d; // OpPushData2
  push.writeUInt16LE(redeemScript.length, 1);
  return Buffer.concat([callBytes, push, redeemScript]).toString("hex");
}

function extractSchnorrSignature(signatureHex, label) {
  const bytes = Buffer.from(signatureHex, "hex");
  if (bytes.length === 66 && bytes[0] === 0x41) {
    return bytes.subarray(1);
  }
  if (bytes.length === 65) {
    return bytes;
  }
  fail(`${label} has unexpected length ${bytes.length}`);
}

/*
 * Execute a delegate spend. `periodsElapsed` null/0 selects the
 * within-period path; >= 1 selects rolloverAndSpend with a CLTV lock time.
 */
async function spendFromVault({ config, vaultId, delegateKey, payAmount, recipientIndex, periodsElapsed = 0 }) {
  const manifest = loadManifest(config, vaultId);
  if (!manifest) {
    fail(`no manifest for vault ${vaultId}`);
  }
  if (manifest.status !== VaultStatus.ACTIVE) {
    fail(`vault status is ${manifest.status} — refusing to spend`);
  }
  const policy = manifest.policy;
  const state = manifest.live.state;
  const pay = BigInt(payAmount);
  const periods = BigInt(periodsElapsed ?? 0);

  const successor =
    periods >= 1n ? rolloverSuccessor(policy, state, pay, periods) : spendSuccessor(state, pay);
  if (periods === 0n && state.periodSpent + pay > policy.periodBudget) {
    fail("spend exceeds the remaining period budget (consider a rollover)");
  }
  if (pay > policy.maxPerSpend) {
    fail("spend exceeds maxPerSpend — the covenant would reject it");
  }
  const idx = Number(recipientIndex);
  if (!Number.isInteger(idx) || idx < 1 || idx > 3) {
    fail("recipientIndex must be 1..3");
  }

  const current = compileExactState({ config, policy, state });
  if (current.scriptSha256 !== manifest.live.scriptSha256) {
    fail("compiled current state does not match the manifest script hash — failing closed");
  }
  const next = compileExactState({ config, policy, state: successor });
  const successorStateId = computeStateId({ networkId: config.networkId, policy, state: successor });
  const nextAddress = covenantAddress(config, next.scriptBytes);
  const currentAddress = covenantAddress(config, current.scriptBytes);

  const lockTime = periods >= 1n ? successor.periodStartDaa : 0n;

  const { rpc, kaspa } = await connectVerified(config);
  try {
    const { PrivateKey, Transaction, CovenantBinding, Hash, payToScriptHashScript, payToAddressScript, createInputSignature } =
      kaspa;

    const delegatePrivate = new PrivateKey(delegateKey.secret);

    /* Exact live covenant UTXO (reference objects for signing). */
    const covResp = await rpc.getUtxosByAddresses({ addresses: [currentAddress] });
    const covRef = (covResp.entries ?? []).find((e) => {
      const outpoint = e.outpoint ?? e.entry?.outpoint;
      return (
        String(outpoint.transactionId).toLowerCase() === manifest.live.outpoint.transactionId &&
        Number(outpoint.index) === manifest.live.outpoint.index
      );
    });
    if (!covRef) {
      fail("the manifest live outpoint is not on chain — reconcile before spending");
    }
    const covAmount = BigInt((covRef.utxoEntry ?? covRef.entry ?? covRef).amount ?? covRef.amount);
    if (covAmount !== state.protectedValue) {
      fail(`live outpoint value ${covAmount} != manifest protectedValue ${state.protectedValue}`);
    }

    /* Delegate fee fuel. */
    const fuelResp = await rpc.getUtxosByAddresses({ addresses: [delegateKey.address] });
    const fuelRefs = (fuelResp.entries ?? []).filter(
      (e) => (e.utxoEntry ?? e.entry ?? e).covenantId === undefined
    );
    if (fuelRefs.length === 0) {
      fail("delegate has no ordinary fee UTXOs");
    }
    const fuelRef = fuelRefs[0];
    const fuelAmount = BigInt((fuelRef.utxoEntry ?? fuelRef.entry ?? fuelRef).amount ?? fuelRef.amount);
    if (fuelAmount <= FEE_PLACEHOLDER_SOMPI) {
      fail("delegate fee UTXO cannot cover the fee");
    }

    const recipientPk = policy.recipients[idx - 1];
    const recipientAddress = new kaspa.PublicKey(`02${recipientPk}`).toAddress(config.networkId).toString();

    const txObject = {
      version: 1,
      inputs: [
        {
          previousOutpoint: {
            transactionId: manifest.live.outpoint.transactionId,
            index: manifest.live.outpoint.index
          },
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: COVENANT_INPUT_COMPUTE_BUDGET,
          utxo: covRef
        },
        {
          previousOutpoint: (fuelRef.outpoint ?? fuelRef.entry?.outpoint),
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: FEE_INPUT_COMPUTE_BUDGET,
          utxo: fuelRef
        }
      ],
      outputs: [
        { value: pay, scriptPublicKey: payToAddressScript(recipientAddress) },
        { value: successor.protectedValue, scriptPublicKey: payToScriptHashScript(next.scriptBytes.toString("hex")) },
        { value: fuelAmount - FEE_PLACEHOLDER_SOMPI, scriptPublicKey: payToAddressScript(delegateKey.address) }
      ],
      lockTime: BigInt(lockTime),
      subnetworkId: "0000000000000000000000000000000000000000",
      gas: 0n,
      payload: ""
    };

    const transaction = new Transaction(txObject);

    /* Successor keeps the lineage covenant id, authorized by input 0. */
    const outs = transaction.outputs;
    outs[1].covenant = new CovenantBinding(0, new Hash(manifest.live.covenantId));
    transaction.outputs = outs;

    const action = periods >= 1n ? "rolloverAndSpend" : "delegateSpend";
    const encoderPaths = {
      sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(current.buildDir, "constructor-args.json")
    };

    /*
     * Re-attach both signatures. Called twice by finalizeWithExactFee (once
     * to measure exact mass, once after setting the exact change). The
     * covenant call embeds the fresh Schnorr signature; both inputs are
     * re-signed because the sighash covers the change output.
     */
    function signAll(tx) {
      const rawCovenantSig = createInputSignature(tx, 0, delegatePrivate);
      const covenantSig = extractSchnorrSignature(rawCovenantSig, "covenant signature");
      const call = {
        function: periods >= 1n ? "rolloverAndSpend" : "delegateSpend",
        successor: {
          protectedValue: successor.protectedValue.toString(),
          periodStartDaa: successor.periodStartDaa.toString(),
          periodSpent: successor.periodSpent.toString(),
          paused: 0
        },
        payAmount: pay.toString(),
        recipientIndex: idx,
        signature: Buffer.from(covenantSig).toString("hex")
      };
      if (periods >= 1n) {
        call.periodsElapsed = periods.toString();
      }
      const callHex = runEncoder({ ...encoderPaths, call });
      const ins = tx.inputs;
      ins[0].signatureScript = covenantSigscript(callHex, current.scriptBytes);
      tx.inputs = ins;
      const ins2 = tx.inputs;
      ins2[1].signatureScript = createInputSignature(tx, 1, delegatePrivate);
      tx.inputs = ins2;
      return tx;
    }

    /* Exact source-backed fee, taken only from delegate fuel. */
    const feeResult = finalizeWithExactFee({
      transaction,
      signAll,
      changeIndex: 2,
      totalInputValue: covAmount + fuelAmount,
      relayMargin: RELAY_MARGIN_SOMPI
    });

    /*
     * Finalizer value-conservation check (I9): protected principal must
     * equal payment + successor exactly; the fee comes only from fuel.
     */
    if (state.protectedValue !== pay + successor.protectedValue) {
      fail("value conservation violated: protectedValue != payAmount + successor");
    }
    if (feeResult.actualFee > fuelAmount) {
      fail("fee exceeds available fuel — refusing");
    }

    const txId = transaction.finalize().toString().toLowerCase();

    /* Durable claims: transition (exact outpoint) + submission. */
    claimTransition(config, {
      outpoint: manifest.live.outpoint,
      action,
      txId,
      vaultId,
      stateId: manifest.live.stateId
    });
    claimSubmission(config, { txId, vaultId, action });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      fail(`node returned txid ${returnedTxId}, expected ${txId}`);
    }

    /* Chain proof: successor outpoint live with exact value + lineage id. */
    let proof = null;
    for (let i = 0; i < 30 && !proof; i++) {
      const resp = await rpc.getUtxosByAddresses({ addresses: [nextAddress] });
      proof =
        (resp.entries ?? []).find((e) => {
          const outpoint = e.outpoint ?? e.entry?.outpoint;
          const utxo = e.utxoEntry ?? e.entry ?? e;
          return (
            String(outpoint.transactionId).toLowerCase() === txId &&
            Number(outpoint.index) === 1 &&
            BigInt(utxo.amount) === successor.protectedValue &&
            String(utxo.covenantId).toLowerCase() === manifest.live.covenantId
          );
        }) ?? null;
      if (!proof) {
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    if (!proof) {
      fail(`submitted ${txId} but the successor was not observed — claim preserved; reconcile before retrying`);
    }

    persistManifest(config, {
      ...manifest,
      status: VaultStatus.ACTIVE,
      policy: manifestPolicyInput(policy),
      live: {
        state: {
          protectedValue: successor.protectedValue.toString(),
          periodStartDaa: successor.periodStartDaa.toString(),
          periodSpent: successor.periodSpent.toString(),
          paused: "0"
        },
        stateId: successorStateId,
        outpoint: { transactionId: txId, index: 1 },
        outpointValue: successor.protectedValue.toString(),
        scriptSha256: next.scriptSha256,
        covenantId: manifest.live.covenantId
      },
      creationTxId: manifest.creationTxId,
      latestTransitionTxId: txId
    });

    persistReceipt(config, {
      txId,
      vaultId,
      action,
      proof: {
        successorOutpoint: `${txId}:1`,
        value: successor.protectedValue.toString(),
        requiredFeeSompi: feeResult.requiredFee.toString(),
        actualFeeSompi: feeResult.actualFee.toString()
      }
    });

    appendAudit(config, {
      vaultId,
      action: action === "rolloverAndSpend" ? "delegate_spend_rollover" : "delegate_spend",
      actor: "delegate",
      txId,
      result: "CHAIN_VERIFIED",
      amountSompi: pay.toString(),
      feeSompi: feeResult.actualFee.toString(),
      recipientIndex: idx,
      oldStateId: manifest.live.stateId,
      newStateId: successorStateId
    });

    return { txId, successor, successorStateId, recipientAddress, fee: feeResult };
  } finally {
    await rpc.disconnect();
  }
}

/* Re-render normalized policy back to manifest input form. */
function manifestPolicyInput(policy) {
  return {
    owner: policy.owner,
    delegate: policy.delegate,
    vaultId: policy.vaultId,
    maxPerSpend: policy.maxPerSpend.toString(),
    periodBudget: policy.periodBudget.toString(),
    periodLengthDaa: policy.periodLengthDaa.toString(),
    recipients: policy.recipients.slice(0, policy.declaredRecipientCount),
    initValue: policy.initValue.toString(),
    initPeriodStartDaa: policy.initPeriodStartDaa.toString()
  };
}

module.exports = { spendFromVault, covenantSigscript, runEncoder };
