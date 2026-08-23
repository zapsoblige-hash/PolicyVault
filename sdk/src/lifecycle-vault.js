"use strict";

/*
 * Owner lifecycle controls that keep the vault live: ownerPause and
 * ownerUnpause. Both are #[covenant.singleton] transitions that copy all
 * state except `paused`, keep the full principal in the successor, and
 * require the owner signature.
 *
 * (revoke / rotate / top-up / policy migration are v0.2 template-change
 * transitions — deferred until after the nucleus is testnet-hardened.)
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { compileExactState } = require("./contract-compiler");
const { computeStateId } = require("./vault-state");
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
  throw new Error(`lifecycle-vault: ${message}`);
}

function runEncoder(sourcePath, argsPath, call) {
  const callPath = path.join(os.tmpdir(), `pv-lifecycle-${crypto.randomUUID()}.json`);
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

async function setPaused({ config, vaultId, ownerKey, pause }) {
  const manifest = loadManifest(config, vaultId);
  if (!manifest) {
    fail(`no manifest for vault ${vaultId}`);
  }
  const wantFrom = pause ? VaultStatus.ACTIVE : VaultStatus.PAUSED;
  if (manifest.status !== wantFrom) {
    fail(`vault status is ${manifest.status}, expected ${wantFrom}`);
  }
  const policy = manifest.policy;
  const state = manifest.live.state;
  const successor = {
    protectedValue: state.protectedValue,
    periodStartDaa: state.periodStartDaa,
    periodSpent: state.periodSpent,
    paused: pause ? 1n : 0n
  };

  const current = compileExactState({ config, policy, state });
  if (current.scriptSha256 !== manifest.live.scriptSha256) {
    fail("compiled current state does not match manifest — failing closed");
  }
  const next = compileExactState({ config, policy, state: successor });
  const successorStateId = computeStateId({ networkId: config.networkId, policy, state: successor });
  const currentAddress = covenantAddress(config, current.scriptBytes);
  const nextAddress = covenantAddress(config, next.scriptBytes);
  const fn = pause ? "ownerPause" : "ownerUnpause";

  const { rpc, kaspa } = await connectVerified(config);
  try {
    const { PrivateKey, Transaction, CovenantBinding, Hash, payToScriptHashScript, payToAddressScript, createInputSignature } =
      kaspa;
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
      fail("live outpoint not on chain — reconcile before pausing");
    }

    const fuelResp = await rpc.getUtxosByAddresses({ addresses: [ownerKey.address] });
    const fuelRef = (fuelResp.entries ?? []).find((e) => (e.utxoEntry ?? e.entry ?? e).covenantId === undefined);
    if (!fuelRef) {
      fail("owner has no ordinary fee UTXOs — fund the owner address first");
    }
    const fuelAmount = BigInt((fuelRef.utxoEntry ?? fuelRef.entry ?? fuelRef).amount);
    if (fuelAmount <= FEE_PLACEHOLDER_SOMPI) {
      fail("owner fee UTXO cannot cover the fee");
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
        { value: successor.protectedValue, scriptPublicKey: payToScriptHashScript(next.scriptBytes.toString("hex")) },
        { value: fuelAmount - FEE_PLACEHOLDER_SOMPI, scriptPublicKey: payToAddressScript(ownerKey.address) }
      ],
      lockTime: 0n,
      subnetworkId: "0000000000000000000000000000000000000000",
      gas: 0n,
      payload: ""
    };

    const transaction = new Transaction(txObject);
    const outs = transaction.outputs;
    outs[0].covenant = new CovenantBinding(0, new Hash(manifest.live.covenantId));
    transaction.outputs = outs;

    function signAll(tx) {
      const sig = extractSchnorr(createInputSignature(tx, 0, ownerPrivate));
      const callHex = runEncoder(
        path.join(current.buildDir, "PolicyVault.state.sil"),
        path.join(current.buildDir, "constructor-args.json"),
        {
          function: fn,
          successor: {
            protectedValue: successor.protectedValue.toString(),
            periodStartDaa: successor.periodStartDaa.toString(),
            periodSpent: successor.periodSpent.toString(),
            paused: pause ? 1 : 0
          },
          signature: Buffer.from(sig).toString("hex")
        }
      );
      const ins = tx.inputs;
      ins[0].signatureScript = covenantSigscript(callHex, current.scriptBytes);
      tx.inputs = ins;
      const ins2 = tx.inputs;
      ins2[1].signatureScript = createInputSignature(tx, 1, ownerPrivate);
      tx.inputs = ins2;
      return tx;
    }

    /* Exact source-backed fee, from owner fuel; principal unchanged. */
    const feeResult = finalizeWithExactFee({
      transaction,
      signAll,
      changeIndex: 1,
      totalInputValue: successor.protectedValue + fuelAmount,
      relayMargin: RELAY_MARGIN_SOMPI
    });

    const txId = transaction.finalize().toString().toLowerCase();

    claimTransition(config, { outpoint: manifest.live.outpoint, action: fn, txId, vaultId, stateId: manifest.live.stateId });
    claimSubmission(config, { txId, vaultId, action: fn });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    if (String(submitted.transactionId ?? submitted).toLowerCase() !== txId) {
      fail("node returned an unexpected txid");
    }

    let proof = null;
    for (let i = 0; i < 30 && !proof; i++) {
      const resp = await rpc.getUtxosByAddresses({ addresses: [nextAddress] });
      proof =
        (resp.entries ?? []).find((e) => {
          const o = e.outpoint ?? e.entry?.outpoint;
          const utxo = e.utxoEntry ?? e.entry ?? e;
          return (
            String(o.transactionId).toLowerCase() === txId &&
            Number(o.index) === 0 &&
            BigInt(utxo.amount) === successor.protectedValue &&
            String(utxo.covenantId).toLowerCase() === manifest.live.covenantId
          );
        }) ?? null;
      if (!proof) {
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    if (!proof) {
      fail(`submitted ${txId} but the successor was not observed — claim preserved; reconcile`);
    }

    persistManifest(config, {
      ...manifest,
      status: pause ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
      policy: manifestPolicyInput(policy),
      live: {
        state: {
          protectedValue: successor.protectedValue.toString(),
          periodStartDaa: successor.periodStartDaa.toString(),
          periodSpent: successor.periodSpent.toString(),
          paused: pause ? "1" : "0"
        },
        stateId: successorStateId,
        outpoint: { transactionId: txId, index: 0 },
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
      action: fn,
      proof: {
        successorOutpoint: `${txId}:0`,
        requiredFeeSompi: feeResult.requiredFee.toString(),
        actualFeeSompi: feeResult.actualFee.toString()
      }
    });
    appendAudit(config, {
      vaultId,
      action: pause ? "vault_paused" : "vault_unpaused",
      actor: "owner",
      txId,
      result: "CHAIN_VERIFIED",
      feeSompi: feeResult.actualFee.toString(),
      oldStateId: manifest.live.stateId,
      newStateId: successorStateId
    });

    return { txId, successorStateId, paused: pause, fee: feeResult };
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

module.exports = {
  pauseVault: (args) => setPaused({ ...args, pause: true }),
  unpauseVault: (args) => setPaused({ ...args, pause: false })
};
