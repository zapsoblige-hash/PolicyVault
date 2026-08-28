"use strict";

/*
 * Vault genesis: fund a new PolicyVault covenant from an ordinary wallet.
 *
 * Stages inside one call, each gated: compile exact CREATED state → build
 * funding tx (covenant output + optional delegate fee-fuel + change) →
 * attach genesis covenant binding → converge fees → sign → preflight →
 * durable claims → submit → chain proof → persist ACTIVE manifest.
 *
 * The genesis transaction spends only ordinary UTXOs; no covenant
 * execution happens at creation.
 */

const { compileExactState } = require("./contract-compiler");
const { normalizePolicy, normalizeState, computeStateId } = require("./vault-state");
const { covenantAddress, connectVerified, getAddressUtxos } = require("./chain");
const { claimSubmission, persistReceipt } = require("./submission-claim");
const { persistManifest, VaultStatus, MANIFEST_SCHEMA } = require("./manifest");
const { CONTRACT_VERSION } = require("./config");
const { appendAudit } = require("./audit");
const { finalizeWithExactFee } = require("./fee-mass");

/*
 * The exact fee is set by finalizeWithExactFee (docs/fee-mass-spec.md).
 * The generator priorityFee below is only a UTXO-selection reservation so
 * change retains headroom for the exact fee; the final change/fee are
 * recomputed exactly afterwards.
 */
const RELAY_MARGIN_SOMPI = 0n;
const FEE_MARGIN_SOMPI = 10_000n;
const MASS_ALLOWANCE_GRAMS = 600n;
const PLACEHOLDER_SIGNATURE_BYTES = 66;
/* Toccata (tx version 1): inputs carry a compute budget, sigOpCount 0. */
const STANDARD_INPUT_COMPUTE_BUDGET = 10;

function fail(message) {
  throw new Error(`create-vault: ${message}`);
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

/*
 * Create and fund a vault on the verified network. `fundingKey` and
 * `delegateFuelSompi` are testnet conveniences; in production the owner
 * wallet signs the funding transaction.
 */
async function createVault({ config, policyInput, fundingKey, delegateAddress, delegateFuelSompi = 0n }) {
  const policy = normalizePolicy(policyInput);
  const createdState = normalizeState({
    protectedValue: policy.initValue,
    periodStartDaa: policy.initPeriodStartDaa,
    periodSpent: "0",
    paused: "0"
  });
  const stateId = computeStateId({ networkId: config.networkId, policy, state: createdState });
  const compiled = compileExactState({ config, policy, state: createdState });
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

    const outputs = [{ address: vaultAddress, amount: policy.initValue }];
    if (delegateFuelSompi > 0n) {
      outputs.push({ address: delegateAddress, amount: delegateFuelSompi });
    }

    /*
     * The generator's fee accounting is accurate for the pre-binding
     * shape; the priority fee covers the covenant-binding bytes it cannot
     * know about (36 bytes ≈ 3,600 sompi) plus headroom. The wasm
     * post-hoc mass/fee recalculators are NOT reliable for version-1
     * transactions (observed 1525/1526/2459 vs node 2495) — do not trust
     * them for adjustments.
     */
    const generated = await createTransactions({
      outputs,
      changeAddress: fundingAddress,
      priorityFee: MASS_ALLOWANCE_GRAMS * 100n + FEE_MARGIN_SOMPI,
      entries: fundingEntries,
      networkId: config.networkId
    });
    if (generated.transactions.length !== 1) {
      fail(`expected one funding transaction, generated ${generated.transactions.length}`);
    }
    const transaction = generated.transactions[0].transaction;
    transaction.version = 1;

    /* Placeholder signatures give accurate signed-mass estimates. */
    const placeholder = new ScriptBuilder().addData(Buffer.alloc(PLACEHOLDER_SIGNATURE_BYTES, 0x66)).drain();
    const inputs = transaction.inputs;
    for (let i = 0; i < inputs.length; i++) {
      inputs[i].sigOpCount = 0;
      inputs[i].computeBudget = STANDARD_INPUT_COMPUTE_BUDGET;
      inputs[i].signatureScript = placeholder;
    }
    transaction.inputs = inputs;

    const covenantSpk = payToScriptHashScript(compiled.scriptBytes.toString("hex"));
    const covenantSpkStr = covenantSpk.toString();
    const outputsNow = transaction.outputs;
    const vaultOutputIndex = outputsNow.findIndex(
      (o) => o.scriptPublicKey.toString() === covenantSpkStr && BigInt(o.value) === policy.initValue
    );
    if (vaultOutputIndex < 0) {
      fail("could not locate the covenant output");
    }
    const changeIndex = outputsNow.findIndex(
      (o, i) => i !== vaultOutputIndex && o.scriptPublicKey.toString() !== covenantSpkStr && (delegateFuelSompi === 0n || BigInt(o.value) !== delegateFuelSompi)
    );
    if (changeIndex < 0) {
      fail("could not locate the change output — funding UTXOs too close to the vault amount");
    }

    /* Genesis covenant id binds input 0's outpoint to the unbound output. */
    const unboundVaultOutput = new TransactionOutput(policy.initValue, covenantSpk);
    const genesisCovenantId = covenantId(transaction.inputs[0].previousOutpoint, [
      { index: vaultOutputIndex, output: unboundVaultOutput }
    ]);
    const genesisCovenantIdHex = genesisCovenantId.toString();

    const boundOutputs = transaction.outputs;
    boundOutputs[vaultOutputIndex].covenant = new CovenantBinding(0, genesisCovenantId);
    transaction.outputs = boundOutputs;

    /*
     * Exact source-backed fee (docs/fee-mass-spec.md). All funding inputs
     * are ordinary p2pk (fixed-width signatures), so re-sign converges in
     * one pass. The covenant output value is not the change output, so the
     * fee comes only from ordinary funding change.
     */
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

    /* Preflight (no broadcast): exact structural checks. */
    const finalOutputs = transaction.outputs;
    if (BigInt(finalOutputs[vaultOutputIndex].value) !== policy.initValue) {
      fail("preflight: covenant output value drifted");
    }
    if (serverInfo.networkId !== config.networkId) {
      fail("preflight: network drifted");
    }

    /* Durable claim before broadcast. */
    await claimSubmission(config, { txId, vaultId: policy.vaultId, action: "createVault" });

    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      fail(`node returned txid ${returnedTxId}, expected ${txId} — refusing to proceed`);
    }

    /* Chain proof: the exact covenant outpoint must appear with the exact
     * value and covenant id. */
    const proof = await pollForProof(async () => {
      const utxos = await getAddressUtxos(rpc, vaultAddress);
      return (
        utxos.find(
          (u) =>
            u.outpoint.transactionId === txId &&
            u.outpoint.index === vaultOutputIndex &&
            u.amount === policy.initValue &&
            u.covenantId === genesisCovenantIdHex.toLowerCase()
        ) ?? null
      );
    });
    if (!proof) {
      fail(
        `submitted ${txId} but the covenant outpoint was not observed — ` +
          "claim preserved; run reconciliation before any retry"
      );
    }

    const manifest = await persistManifest(config, {
      schema: MANIFEST_SCHEMA,
      contractVersion: CONTRACT_VERSION,
      networkId: config.networkId,
      vaultId: policy.vaultId,
      label: policyInput.label ?? "",
      status: VaultStatus.ACTIVE,
      policy: policyInput,
      live: {
        state: {
          protectedValue: createdState.protectedValue.toString(),
          periodStartDaa: createdState.periodStartDaa.toString(),
          periodSpent: "0",
          paused: "0"
        },
        stateId,
        outpoint: { transactionId: txId, index: vaultOutputIndex },
        outpointValue: createdState.protectedValue.toString(),
        scriptSha256: compiled.scriptSha256,
        covenantId: genesisCovenantIdHex.toLowerCase()
      },
      creationTxId: txId,
      latestTransitionTxId: null
    });

    await persistReceipt(config, {
      txId,
      vaultId: policy.vaultId,
      action: "createVault",
      proof: {
        outpoint: proof.outpoint,
        amount: proof.amount.toString(),
        covenantId: proof.covenantId,
        requiredFeeSompi: feeResult.requiredFee.toString(),
        actualFeeSompi: feeResult.actualFee.toString()
      }
    });

    await appendAudit(config, {
      vaultId: policy.vaultId,
      action: "vault_created",
      actor: "owner",
      txId,
      result: "CHAIN_VERIFIED",
      feeSompi: feeResult.actualFee.toString(),
      newStateId: stateId
    });

    return { txId, vaultAddress, vaultOutputIndex, covenantId: genesisCovenantIdHex.toLowerCase(), stateId, manifest, fee: feeResult };
  } finally {
    await rpc.disconnect();
  }
}

module.exports = { createVault };
