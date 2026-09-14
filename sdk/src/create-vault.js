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
const { claimSubmission } = require("./submission-claim");
const { assertVaultIdentityFree, withVaultIdentityLock, normalizeVaultId } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): global vault-record uniqueness
const { CONTRACT_VERSION } = require("./config");
const { finalizeWithExactFee } = require("./fee-mass");
/* RC35-RES-01 (2026-09-11): the durable headless creation record (identity reservation bound to the creator and the exact
 * expected outcome BEFORE any chain effect), the shared submit-outcome settlement and ONE replayable create-only completion */
const { openHeadlessCreation, saveHeadlessCreation, settleHeadlessBroadcast, completeHeadlessCreation } = require("./headless-creation");

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
    if (i + 1 < attempts) await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return null;
}

/*
 * Create and fund a vault on the verified network. `fundingKey` and
 * `delegateFuelSompi` are testnet conveniences; in production the owner
 * wallet signs the funding transaction.
 */
/* RC33-ID-01 review finding F3 (2026-09-11): the whole flow (check -> build -> record -> claim -> broadcast -> create-only
 * completion) runs under the per-identity lock against in-process builders; a malformed policy falls through and is refused
 * exactly as before. RC35-RES-01: the durable headless creation record (sdk/src/headless-creation.js) is written the moment
 * the signed transaction exists — BEFORE the submission claim and BEFORE the broadcast — so the identity stays reserved
 * across any restart and the exact outcome is recoverable by observation only (recoverHeadlessCreation). `connection`
 * ({ rpc, kaspa, serverInfo }) lets an isolated test drive the real flow against a mock node; production uses the verified
 * node connection. */
async function createVault(args) {
  let vaultId = null;
  try { vaultId = normalizeVaultId(normalizePolicy(args.policyInput).vaultId); } catch { vaultId = null; }
  if (vaultId === null) return createVaultUnlocked(args);
  return withVaultIdentityLock(vaultId, () => createVaultUnlocked(args));
}
async function createVaultUnlocked({ config, policyInput, fundingKey, delegateAddress, delegateFuelSompi = 0n, connection = null, pollAttempts = 30, pollDelayMs = 2000 }) {
  const policy = normalizePolicy(policyInput);
  await assertVaultIdentityFree(config, policy.vaultId); // RC33-ID-01: an identity held by ANY generation's record, ANY request or ANY retained submission claim is refused before anything is built, claimed or sent
  const createdState = normalizeState({
    protectedValue: policy.initValue,
    periodStartDaa: policy.initPeriodStartDaa,
    periodSpent: "0",
    paused: "0"
  });
  const stateId = computeStateId({ networkId: config.networkId, policy, state: createdState });
  const compiled = compileExactState({ config, policy, state: createdState });
  const vaultAddress = covenantAddress(config, compiled.scriptBytes);

  const owned = !connection;
  const { rpc, kaspa, serverInfo } = owned ? await connectVerified(config) : connection;
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

    /* RC35-RES-01: the DURABLE headless creation record — the identity is bound to the creator and the exact expected
     * outcome BEFORE the submission claim and BEFORE the broadcast (from here on it survives any restart). */
    const creation = await openHeadlessCreation(config, {
      generation: "v1", action: "createVault", contractVersion: CONTRACT_VERSION, vaultId: policy.vaultId, creator: fundingAddress, label: policyInput.label ?? "",
      definition: { policyInput },
      expected: { address: vaultAddress, index: vaultOutputIndex, value: policy.initValue.toString(), covenantId: genesisCovenantIdHex.toLowerCase(), scriptSha256: compiled.scriptSha256, stateId },
      txId, signedSafeJson: transaction.serializeToSafeJSON()
    });
    /* Durable claim before broadcast. */
    await claimSubmission(config, { txId, vaultId: policy.vaultId, action: "createVault" });
    creation.submitStartHash = await require("./submission-outcome-v7").readSubmissionStartHash(rpc);
    creation.state = "SUBMITTING";
    await saveHeadlessCreation(config, creation);

    let submitted;
    try {
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      /* RC35-REC-01: REJECTED (bound rejection + output verified absent) settles the negative and releases the claim; an
       * already-known answer is observed like an accepted response; anything else keeps the claim (RECONCILIATION_REQUIRED) */
      const settled = await settleHeadlessBroadcast(config, rpc, creation, e);
      if (settled.decision !== "OBSERVE") throw settled.error;
      submitted = { transactionId: txId };
    }
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== txId) {
      creation.state = "RECONCILIATION_REQUIRED";
      creation.error = `node returned txid ${returnedTxId}, expected ${txId}`;
      await saveHeadlessCreation(config, creation);
      fail(`node returned txid ${returnedTxId}, expected ${txId} — refusing to proceed (claim and record preserved; recover with recoverHeadlessCreation)`);
    }
    creation.state = "SUBMITTED";
    await saveHeadlessCreation(config, creation);

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
    }, { attempts: pollAttempts, delayMs: pollDelayMs });
    if (!proof) {
      creation.state = "RECONCILIATION_REQUIRED";
      creation.error = `submitted ${txId} but the covenant outpoint was not observed — claim and record preserved; recover by observation (recoverHeadlessCreation), never by a retry`;
      await saveHeadlessCreation(config, creation);
      fail(
        `submitted ${txId} but the covenant outpoint was not observed — ` +
          "claim preserved; run reconciliation (recoverHeadlessCreation) before any retry"
      );
    }

    /* RC33-ID-01 + RC35-RES-01: ONE replayable create-only completion (manifest, receipt, audit, own-claim release, record) */
    const { manifest } = await completeHeadlessCreation(config, creation, proof, { fee: feeResult, via: "create" });

    return { txId, vaultAddress, vaultOutputIndex, covenantId: genesisCovenantIdHex.toLowerCase(), stateId, manifest, fee: feeResult, requestId: creation.requestId };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

module.exports = { createVault };
