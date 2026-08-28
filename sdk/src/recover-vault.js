"use strict";

/*
 * Owner recovery: terminate the vault lineage and move the full remaining
 * protected principal to the owner key. Only the owner authority can
 * execute this; the delegate cannot. Works regardless of pause state.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { compileExactState } = require("./contract-compiler");
const { covenantAddress, connectVerified } = require("./chain");
const { claimTransition, claimSubmission, persistReceipt } = require("./submission-claim");
const { loadManifest, persistManifest, VaultStatus } = require("./manifest");
const { covenantSigscript } = require("./spend-vault");
const { appendAudit } = require("./audit");
const { finalizeWithExactFee } = require("./fee-mass");

const ENCODER_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder");
const COVENANT_INPUT_COMPUTE_BUDGET = 100;
const FEE_INPUT_COMPUTE_BUDGET = 10;
const RELAY_MARGIN_SOMPI = 0n;
const FEE_PLACEHOLDER_SOMPI = 5_000_000n;

function fail(message) {
  throw new Error(`recover-vault: ${message}`);
}

function runEncoder(sourcePath, argsPath, call) {
  const callPath = path.join(os.tmpdir(), `pv-recover-${crypto.randomUUID()}.json`);
  fs.writeFileSync(callPath, JSON.stringify(call));
  try {
    const r = spawnSync(ENCODER_PATH, [sourcePath, argsPath, callPath], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    if (r.status !== 0) {
      fail(`encoder failed: ${r.stderr?.trim()}`);
    }
    return r.stdout.trim();
  } finally {
    fs.unlinkSync(callPath);
  }
}

function extractSchnorr(hex) {
  const b = Buffer.from(hex, "hex");
  return b.length === 66 && b[0] === 0x41 ? b.subarray(1) : b;
}

async function recoverVault({ config, vaultId, ownerKey }) {
  const manifest = await loadManifest(config, vaultId);
  if (!manifest) {
    fail(`no manifest for vault ${vaultId}`);
  }
  if (manifest.status !== VaultStatus.ACTIVE && manifest.status !== VaultStatus.PAUSED) {
    fail(`vault status is ${manifest.status} — cannot recover`);
  }
  const policy = manifest.policy;
  const state = manifest.live.state;

  const current = compileExactState({ config, policy, state });
  if (current.scriptSha256 !== manifest.live.scriptSha256) {
    fail("compiled current state does not match manifest — failing closed");
  }
  const currentAddress = covenantAddress(config, current.scriptBytes);

  const { rpc, kaspa } = await connectVerified(config);
  try {
    const { PrivateKey, Transaction, payToAddressScript, createInputSignature } = kaspa;
    const ownerPrivate = new PrivateKey(ownerKey.secret);

    const covResp = await rpc.getUtxosByAddresses({ addresses: [currentAddress] });
    const covRef = (covResp.entries ?? []).find((e) => {
      const o = e.outpoint ?? e.entry?.outpoint;
      return (
        String(o.transactionId).toLowerCase() === manifest.live.outpoint.transactionId &&
        Number(o.index) === manifest.live.outpoint.index
      );
    });
    if (!covRef) {
      fail("live outpoint not on chain — reconcile before recovering");
    }

    /* Owner supplies fee fuel from their own address. */
    const fuelResp = await rpc.getUtxosByAddresses({ addresses: [ownerKey.address] });
    const fuelRef = (fuelResp.entries ?? []).find((e) => (e.utxoEntry ?? e.entry ?? e).covenantId === undefined);
    if (!fuelRef) {
      fail("owner has no ordinary fee UTXOs — fund the owner address first");
    }
    const fuelAmount = BigInt((fuelRef.utxoEntry ?? fuelRef.entry ?? fuelRef).amount);
    if (fuelAmount <= FEE_PLACEHOLDER_SOMPI) {
      fail("owner fee UTXO cannot cover the recovery fee");
    }

    const txObject = {
      version: 1,
      inputs: [
        {
          previousOutpoint: manifest.live.outpoint,
          signatureScript: "",
          sequence: 0n,
          sigOpCount: 0,
          computeBudget: COVENANT_INPUT_COMPUTE_BUDGET,
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

    function signAll(tx) {
      const sig = extractSchnorr(createInputSignature(tx, 0, ownerPrivate));
      const callHex = runEncoder(
        path.join(current.buildDir, "PolicyVault.state.sil"),
        path.join(current.buildDir, "constructor-args.json"),
        { function: "ownerRecover", signature: Buffer.from(sig).toString("hex") }
      );
      const ins = tx.inputs;
      ins[0].signatureScript = covenantSigscript(callHex, current.scriptBytes);
      tx.inputs = ins;
      const ins2 = tx.inputs;
      ins2[1].signatureScript = createInputSignature(tx, 1, ownerPrivate);
      tx.inputs = ins2;
      return tx;
    }

    /* Exact source-backed fee, taken only from owner fuel. */
    const feeResult = finalizeWithExactFee({
      transaction,
      signAll,
      changeIndex: 1,
      totalInputValue: state.protectedValue + fuelAmount,
      relayMargin: RELAY_MARGIN_SOMPI
    });

    const txId = transaction.finalize().toString().toLowerCase();

    await claimTransition(config, {
      outpoint: manifest.live.outpoint,
      action: "ownerRecover",
      txId,
      vaultId,
      stateId: manifest.live.stateId
    });
    await claimSubmission(config, { txId, vaultId, action: "ownerRecover" });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      fail(`node returned txid ${returnedTxId}, expected ${txId}`);
    }

    /* Terminal chain proof: the covenant outpoint is consumed and gone. */
    let gone = false;
    for (let i = 0; i < 30 && !gone; i++) {
      const resp = await rpc.getUtxosByAddresses({ addresses: [currentAddress] });
      const stillThere = (resp.entries ?? []).some((e) => {
        const o = e.outpoint ?? e.entry?.outpoint;
        return (
          String(o.transactionId).toLowerCase() === manifest.live.outpoint.transactionId &&
          Number(o.index) === manifest.live.outpoint.index
        );
      });
      gone = !stillThere;
      if (!gone) {
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    if (!gone) {
      fail(`submitted ${txId} but the covenant outpoint is still live — claim preserved; reconcile`);
    }

    await persistManifest(config, {
      ...manifest,
      status: VaultStatus.RECOVERED,
      policy: manifestPolicyInput(policy),
      live: null,
      latestTransitionTxId: txId
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

module.exports = { recoverVault };
