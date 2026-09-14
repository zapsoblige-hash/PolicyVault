"use strict";

/*
 * SUBMIT-OUTCOME SETTLEMENT + OBSERVATION-ONLY GENESIS RECOVERY PRIMITIVES — RC35-REC-01 / REC-02 / legacy F4
 * (independent RC35 affected review, 2026-09-11; owner recovery/reservation repair directive of the same day).
 *
 * Shared by every submitter and every genesis recovery path (headless v0.1 / v0.2, v0.2 requests, v0.4.1, v0.5, v0.6,
 * v0.7 root + rooted genesis, v0.7-payment-hd, v0.7-kas). Everything here is READ-ONLY on chain: nothing is built,
 * signed, rebroadcast or erased. The callers own their durable records; this module decides and observes.
 *
 *   settleGenesisSubmitError      the node answered a genesis broadcast with an error. Decides, from the shared
 *                                 classification (sdk/src/submission-classification.js) AND a chain check:
 *                                   OBSERVE    ALREADY_KNOWN — the node holds / accepted this transaction: keep the
 *                                              claim, proceed exactly as after an accepted response;
 *                                   REJECTED   a bound rejection plus complete original-anchor nonacceptance,
 *                                              exact funding and mempool/output proof — release the claim,
 *                                              SUBMISSION_REJECTED with a proof the identity arbiter recognizes;
 *                                   UNCERTAIN  AMBIGUOUS (transport / unbound envelope), or a rejection whose output
 *                                              IS observed (a contradiction), or an output check that itself failed:
 *                                              keep the claim, RECONCILIATION_REQUIRED.
 *   settleTransitionSubmitError   the same for a covenant transition: REJECTED only when the predecessor is still
 *                                 live AND the expected effect is absent (both checks succeeded); otherwise UNCERTAIN.
 *   observeOutputUnderTxId        the exact expected output of a frozen transaction, or any output under its txid.
 *   ensureOwnSubmissionClaim      re-establish (or confirm) the submission claim that binds a txid to THIS request's
 *                                 operation — idempotent, and it NEVER takes over a claim that names another
 *                                 operation (CLAIM_CONFLICT instead).
 *   unobservedRecoveryDisposition what a recovery path does with a request whose output is NOT observed: an
 *                                 ESTABLISHED negative is kept as it is (nothing rebroadcast, nothing rewritten); a
 *                                 false negative (the reviewer's case: the stored node answer was ALREADY_KNOWN) or
 *                                 an unknown legacy answer is PROTECTED (claim re-established, RECONCILIATION_REQUIRED);
 *                                 any other unresolved state stays unresolved with its claim.
 */

const { getStore, Categories } = require("./store");
const { getAddressUtxos, loadKaspa } = require("./chain");
const { claimSubmission } = require("./submission-claim");
const { classifySubmitOutcome, classifyRecordedNegative, firstLine, NEGATIVE_PROOF_SCHEMA, NON_ACCEPTANCE_PROOF_SCHEMA, negativeEvidenceBinding } = require("./submission-classification");

function fail(message, code) {
  const e = new Error(`genesis-recovery: ${message}`);
  e.code = code;
  return e;
}

/*
 * Observe the output a frozen transaction declares: expected = { address, txId, index, value?, covenantId? }.
 *   { ref: null, exact: false }   nothing under this txid:index at the address
 *   { ref, exact: true }          the exact expected output (value and covenant id match when given)
 *   { ref, exact: false }         an output under this txid:index exists but differs — still a chain effect of THIS
 *                                 transaction (a negative verdict is contradicted; a completion must not accept it)
 * Throws when the node cannot answer (uncertainty is never read as absence).
 */
async function observeOutputUnderTxId(rpc, expected) {
  const txId = String(expected.txId).toLowerCase();
  const index = Number(expected.index);
  const refs = await getAddressUtxos(rpc, expected.address);
  const ref = refs.find((u) => u.outpoint.transactionId === txId && u.outpoint.index === index) ?? null;
  if (!ref) return { ref: null, exact: false };
  const valueOk = expected.value === undefined || expected.value === null || String(ref.amount) === String(expected.value);
  const covenantOk = expected.covenantId === undefined || expected.covenantId === null || String(ref.covenantId ?? "").toLowerCase() === String(expected.covenantId).toLowerCase();
  return { ref, exact: valueOk && covenantOk };
}

/* The canonical address of a frozen output / input UTXO script ({ version, scriptHex }) on this network. */
function frozenScriptAddress(config, scriptPublicKey) {
  const address = loadKaspa(config).addressFromScriptPublicKey({ version: scriptPublicKey.version, script: scriptPublicKey.scriptHex }, config.networkId);
  if (!address) throw fail("could not derive an address from a frozen scriptPublicKey — internal", "RECONCILIATION_REQUIRED");
  return address.toString();
}

/* true when ANY output of the frozen transaction is observed unspent under its txid (a chain effect of THIS
 * transaction exists — a negative verdict is contradicted). Throws when the node cannot answer. */
async function anyFrozenOutputObserved(config, rpc, frozen, txId) {
  const id = String(txId).toLowerCase();
  for (let i = 0; i < frozen.outputs.length; i++) {
    const refs = await getAddressUtxos(rpc, frozenScriptAddress(config, frozen.outputs[i].scriptPublicKey));
    if (refs.some((u) => u.outpoint.transactionId === id)) return true;
  }
  return false;
}

/* true when the frozen transaction's input `index` is still UNSPENT at its own UTXO address (the predecessor is live).
 * Throws when the node cannot answer. */
async function frozenInputLive(config, rpc, frozen, index) {
  const input = frozen.inputs[index];
  if (!input || !input.utxo || !input.utxo.scriptPublicKey) throw fail(`frozen input ${index} carries no UTXO script — cannot check the predecessor`, "RECONCILIATION_REQUIRED");
  const refs = await getAddressUtxos(rpc, frozenScriptAddress(config, input.utxo.scriptPublicKey));
  const want = { transactionId: String(input.previousOutpoint.transactionId).toLowerCase(), index: Number(input.previousOutpoint.index) };
  return refs.some((u) => u.outpoint.transactionId === want.transactionId && u.outpoint.index === want.index);
}

/* Extract the immutable funding/output view. Legacy Safe JSON carries funding
 * UTXOs too; missing metadata cannot be reconstructed from a current UTXO miss. */
function negativeFrozenView(request, config) {
  if (request?.build?.frozen) return request.build.frozen;
  const safe = request?.transaction?.unsignedSafeJson ?? request?.signedSafeJson;
  if (typeof safe !== "string" || !config) throw Error("no immutable funding transaction");
  // Safe JSON encodes ScriptPublicKey as version-prefixed hex, unlike the
  // frozen model. Decode it with the same WASM engine that wrote it.
  const tx = loadKaspa(config).Transaction.deserializeFromSafeJSON(safe);
  const script = (s) => ({ version: Number(s.version), scriptHex: String(s.script).toLowerCase() });
  return {
    inputs: tx.inputs.map((i) => ({ previousOutpoint: { transactionId: i.previousOutpoint.transactionId.toString().toLowerCase(), index: Number(i.previousOutpoint.index) },
      utxo: i.utxo && { amount: String(i.utxo.amount), covenantId: i.utxo.covenantId?.toString().toLowerCase() ?? null, scriptPublicKey: script(i.utxo.scriptPublicKey) } })),
    outputs: tx.outputs.map((o) => ({ value: String(o.value), scriptPublicKey: script(o.scriptPublicKey) }))
  };
}

/* A missing current output may have been spent. Settlement requires a complete
 * nonreorged original-anchor acceptance window excluding this exact transaction,
 * a stable final sink, exact funding inputs unspent twice, mempool misses and every
 * output absent around those reads. Errors, missing metadata and contradictions
 * retain the claim. This is a coherent rejection-of-this-attempt proof; it is not
 * a historical transaction lookup or a claim that an absent output never existed. */
async function proveFundingNonAcceptance(config, rpc, request, txId) {
  // The caller may use this coherent nonacceptance snapshot for an ordinary
  // uncertain attempt; a stored positive node answer contradicts that use.
  if (request?.submissionResponse?.kind === "ALREADY_KNOWN" || classifySubmitOutcome(request?.error, txId).kind === "ALREADY_KNOWN") return null;
  if (!config || !rpc || request?.txId !== txId || !negativeEvidenceBinding(request) || !/^[0-9a-f]{64}$/.test(request.submitStartHash ?? "")) throw Error("negative proof lacks its bound request");
  const frozen = negativeFrozenView(request, config);
  if (!Array.isArray(frozen.inputs) || !frozen.inputs.length || !Array.isArray(frozen.outputs) || !frozen.outputs.length) throw Error("negative proof lacks funding inputs or outputs");
  const keys = frozen.inputs.map((i) => `${i.previousOutpoint.transactionId}:${i.previousOutpoint.index}`);
  if (new Set(keys).size !== keys.length) throw Error("duplicate frozen funding input");
  // Derive the consensus txid from these exact immutable fields, never sign or submit.
  let actual;
  if (request.build?.frozen) actual = require("./frozen-tx-v3").frozenToWasmTransaction(config, require("./frozen-tx-v3").normalizeFrozenTxV3(frozen)).finalize().toString().toLowerCase();
  else actual = loadKaspa(config).Transaction.deserializeFromSafeJSON(request.transaction?.unsignedSafeJson ?? request.signedSafeJson).finalize().toString().toLowerCase();
  if (actual !== txId) throw Error("funding transaction differs from the recorded txid");
  async function inputsLive() {
    for (const i of frozen.inputs) {
      const u = i.utxo;
      if (!u?.scriptPublicKey || u.amount === undefined) throw Error("frozen funding metadata is incomplete");
      const refs = await getAddressUtxos(rpc, frozenScriptAddress(config, u.scriptPublicKey));
      const matches = refs.filter((r) => r.outpoint.transactionId === i.previousOutpoint.transactionId && r.outpoint.index === Number(i.previousOutpoint.index));
      if (matches.length !== 1) return false;
      const r = matches[0];
      if (String(r.amount) !== String(u.amount) || r.scriptPublicKeyHex !== u.scriptPublicKey.scriptHex || (r.covenantId ?? null) !== (u.covenantId ?? null)) throw Error("funding observation differs from immutable input");
    }
    return true;
  }
  async function mempoolAbsent() {
    const { isExactMempoolMiss } = require("./wallet-submit-v4");
    try { await rpc.getMempoolEntry({ transactionId: txId, includeOrphanPool: true, filterTransactionPool: false }); }
    catch (e) { if (isExactMempoolMiss(e, txId)) return true; throw e; }
    return false; // present OR malformed success: neither proves absence
  }
  const observer = require("./submission-outcome-v7");
  const window = await observer.acceptanceWindow(rpc, request.submitStartHash, txId, false);
  if (!window.complete || window.initialAnchorReorg || window.accepted) return null;
  if (await anyFrozenOutputObserved(config, rpc, frozen, txId) || !await mempoolAbsent() || !await inputsLive() ||
      await anyFrozenOutputObserved(config, rpc, frozen, txId) || !await inputsLive() ||
      !await mempoolAbsent() || await anyFrozenOutputObserved(config, rpc, frozen, txId)) return null;
  if (await observer.readSubmissionStartHash(rpc) !== window.sink) return null;
  return { schema: NON_ACCEPTANCE_PROOF_SCHEMA, txId, startHash: request.submitStartHash, sink: window.sink,
    completeAcceptanceWindow: true, initialAnchorReorg: false, requestBinding: negativeEvidenceBinding(request),
    allInputsUnspent: true, repeatedFundingQueries: true,
    exactMempoolMiss: true, outputsAbsent: true, at: new Date().toISOString() };
}

async function proveUnacceptedFunding(config, rpc, request, txId) {
  if (request?.genesisRecovery || request?.submissionRejection || classifySubmitOutcome(request?.error, txId).kind !== "AMBIGUOUS") return null;
  return proveFundingNonAcceptance(config, rpc, request, txId);
}

async function proveRejectedFunding(config, rpc, request, txId, message) {
  if (classifySubmitOutcome(message, txId).kind !== "REJECTED") return null;
  const proof = await proveFundingNonAcceptance(config, rpc, request, txId);
  return proof && { ...proof, schema: NEGATIVE_PROOF_SCHEMA, boundRejection: true, nodeAnswer: firstLine(message) };
}

async function settleGenesisSubmitError({ config, rpc, request, message, txId, expected }) {
  const classification = classifySubmitOutcome(message, txId);
  if (classification.kind === "ALREADY_KNOWN") return { decision: "OBSERVE", classification, reason: `the node already holds / accepted ${txId} (${classification.variant}) — observing with claim kept` };
  if (classification.kind === "REJECTED") {
    if (request && !request.submissionRejection) request.submissionRejection = {
      txId, message: firstLine(message), submitStartHash: request.submitStartHash ?? null
    };
    try {
      const proof = await proveRejectedFunding(config, rpc, request, txId, message);
      if (proof) return { decision: "REJECTED", classification, proof };
      return { decision: "UNCERTAIN", classification, reason: "the rejection lacks a coherent unspent-funding / mempool / output proof — claim kept" };
    } catch (e) {
      return { decision: "UNCERTAIN", classification, reason: `negative-outcome verification unavailable (${firstLine(e)}) — claim kept` };
    }
  }
  return { decision: "UNCERTAIN", classification, reason: "no bound node rejection for this attempt — claim kept" };
}

async function refreshUnobservedGenesis({ config, rpc, request, claim, save }) {
  const established = require("./submission-classification").recordedNegativeIsEstablished(request);
  let proof = null;
  const original = request.submissionRejection;
  if (!established && original?.txId === request.txId && original.submitStartHash === request.submitStartHash && classifySubmitOutcome(original.message, request.txId).kind === "REJECTED") {
    try { proof = await proveRejectedFunding(config, rpc, request, request.txId, original.message); } catch { /* preserve uncertainty */ }
  }
  if (established || proof) {
    const store = getStore(config);
    const held = await store.read(Categories.SUBMISSION_CLAIM, request.txId);
    if (held && (held.vaultId !== claim.vaultId || held.action !== claim.action)) throw fail("negative recovery claim belongs to another operation", "CLAIM_CONFLICT");
    if (proof) {
      request.submissionOutcome = { outcome: "SUBMISSION_REJECTED", txId: request.txId, reason: original.message, proof };
      request.state = "SUBMISSION_REJECTED";
      await save(request); // durable proof first; a crash leaves the claim for this retry
    }
    if (held) await require("./submission-claim").releaseSubmissionClaim(config, request.txId);
    return { action: "KEEP_NEGATIVE", negative: "ESTABLISHED" };
  }
  return unobservedRecoveryDisposition(request);
}

async function settleTransitionSubmitError(args) {
  // The full funding proof also covers predecessor and successor. Keep explicit
  // family predicates as additional checks, never as the sole release premise.
  const result = await settleGenesisSubmitError(args);
  if (result.decision !== "REJECTED") return result;
  try {
    if (await args.predecessorLive() === true && await args.effectAbsent() === true) return result;
  } catch { /* unavailable family evidence retains claims */ }
  return { decision: "UNCERTAIN", classification: result.classification, reason: "family predecessor / successor evidence is unavailable or contradictory — claims kept" };
}

/* Re-establish or confirm the submission claim binding txId to THIS operation; never take over another operation's claim. */
async function ensureOwnSubmissionClaim(config, { txId, vaultId, action }) {
  const existing = await getStore(config).read(Categories.SUBMISSION_CLAIM, txId);
  if (existing) {
    if (existing.vaultId !== vaultId || existing.action !== action) {
      throw fail(`the submission claim for ${txId} names another operation (${existing.action} on ${existing.vaultId}) — refusing to take it over; reconcile that operation`, "CLAIM_CONFLICT");
    }
    return "HELD";
  }
  await claimSubmission(config, { txId, vaultId, action });
  return "CREATED";
}

/* The disposition of a request whose expected output is NOT observed during observation-only recovery. */
function unobservedRecoveryDisposition(request) {
  if (request && request.state === "SUBMISSION_REJECTED") {
    const negative = classifyRecordedNegative(request);
    if (negative === "ESTABLISHED") return { action: "KEEP_NEGATIVE", negative };
    const answer = firstLine(request.error) || "(absent)";
    return {
      action: "PROTECT",
      negative,
      reason: negative === "FALSE_NEGATIVE"
        ? `the recorded node answer (${answer}) says the node already held or accepted ${request.txId} — that was never a rejection; the outcome is unresolved and the submission claim is re-established (nothing is rebroadcast)`
        : `the recorded node answer (${answer}) does not establish a rejection of ${request.txId} — the outcome is unresolved and the submission claim is re-established (nothing is rebroadcast)`
    };
  }
  return { action: "UNRESOLVED", negative: null };
}

module.exports = {
  refreshUnobservedGenesis,
  negativeFrozenView,
  proveRejectedFunding,
  proveUnacceptedFunding,
  frozenScriptAddress,
  anyFrozenOutputObserved,
  frozenInputLive,
  observeOutputUnderTxId,
  settleGenesisSubmitError,
  settleTransitionSubmitError,
  ensureOwnSubmissionClaim,
  unobservedRecoveryDisposition
};
