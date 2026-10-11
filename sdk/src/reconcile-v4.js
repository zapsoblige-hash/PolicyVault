"use strict";

/*
 * RECONCILE-ONLY mode for PolicyVault v0.4 vaults: the Verify settlement pass
 * (RC45 F5; plan rc45-simplified-plan-r2 §2.0, §2.2, §2.5(1), §4). Never
 * broadcasts. No force unlock, no manual claim deletion, no request-body
 * override of stale timers or proof requirements — identical philosophy to the
 * hardened reconcile-v2.
 *
 * Verify is the one settlement place. It writes only on positive chain
 * evidence at depth SETTLE_DEPTH_DAA (D = 1,000 DAA), never on age, absence,
 * node errors or caller options. Depth is judged from the node's raw
 * blockDaaScore of the judged entries only; a non-canonical one is a 422 (RC45
 * R1-05). The only writes that need no fresh read
 * finish a recorded advancement (finishRecordedV4), finish a record from its
 * own completion receipt (RC45 R1-06 C2) or RC44's established negative
 * release (releaseEstablishedLeftover).
 *
 * The pass (plan r2 §2.2 step numbers):
 *   0  load, ABI, operational network, manifest network (pure, no write)
 *   1  under withVaultIdentityLock: reload; the vault's requests listed strictly
 *   3  closed vault: finish the recorded advancement and the receipt-matching
 *      records (no node call); any PENDING record -> REQUEST_RECOVERY_REQUIRED,
 *      else TERMINAL; either answer carries settled[] when it finished
 *      something (RC45 R1-13)
 *   4  base = the live state, or for TERMINATED_UNKNOWN the last recorded live
 *      state (none -> UNKNOWN, no write)
 *   6  every Verify reads the recorded outpoint L first. L live: restore
 *      (TERMINATED_UNKNOWN, at D), settleOneHop, releaseEstablishedLeftover;
 *      PENDING ON L -> REQUEST_RECOVERY_REQUIRED; a lone claim -> CLAIM_PENDING;
 *      else CONSISTENT. An environment failure after the restore is still a
 *      422 whose message names the restore (RC45 R1-14)
 *   7  L spent: the recorded requests on L, grouped by txid, are read by output
 *      class under a 64-address cap; one SEEN group, validated, completes at D
 *      (completePositive) and answers CLAIM_PENDING below D; two answer
 *      CHAIN_CONTRADICTION; nothing seen after a failed read is a 422. A
 *      governance-refused unsigned primary only advances the manifest (RC45
 *      R1-03)
 *   8  adoption of an out-of-app pause / unpause at address(S) or
 *      address(pauseSuccessorV4(S)) (plan amendment PA-01 r1: only outputs
 *      with the vault's covenant id are candidates, every other output is
 *      ignored; L or the old outpoint there, a wrong value, a known txid or
 *      more than one candidate -> CHAIN_CONTRADICTION; none -> steps 9-11)
 *   9  owner-pasted recover evidence (RC45 F6, §2.5(3)): the optional
 *      `outOfAppTransaction` (Safe JSON <= 64 KiB, at most 64 outputs, else
 *      BAD_FORMAT at step 0) is a recover of L observed at D -> RECOVERED
 *      (losers first); outputs[0]'s address and at most 4 further distinct
 *      output addresses are read, the rest are counted unchecked (RC45
 *      R1-09); a mismatch settles nothing and the pass continues; below D ->
 *      CLAIM_PENDING
 *  10  the recorded old outpoint live again, or spent by another recorded
 *      txid -> CHAIN_CONTRADICTION
 *  11  UNKNOWN{reason, unchecked}, no write (TERMINATED_UNKNOWN is never written)
 * 422 (unavailable), UNKNOWN (absence) and CHAIN_CONTRADICTION (contradiction)
 * stay distinct and write nothing. A missing predecessor is NEVER treated as
 * success on its own; the paste grants no authority.
 */

const { assertOperationalNetwork } = require("./config");
const { connectVerified, getAddressUtxos, getVirtualDaaScore, canonicalDaaScore } = require("./chain");
const { VaultStatus } = require("./manifest");
const { loadManifestV4, persistManifestV4, normalizeManifestV4 } = require("./manifest-v4");
const { resolveV4Abi, stateToJsonV4, normalizeStateV4, computeStateIdV4 } = require("./vault-state-v4");
const { pauseSuccessorV4 } = require("./vault-transitions-v4");
const { getStore, Categories } = require("./store");
const { transitionClaimKey } = require("./submission-claim");
const { RequestState, REQUEST_SCHEMA_V4, isBreakGlassV4, loadRequest, saveRequest } = require("./wallet-requests-v4");
const { advanceManifestAndRegistryV4, successorAddressAndScript, manifestToJson, releaseOwnTransitionClaimV4 } = require("./wallet-submit-v4");
const { releaseReservationForRequest } = require("./budget-reservation");
const { recordedNegativeIsEstablished } = require("./submission-classification");
const { frozenScriptAddress } = require("./genesis-recovery");
const { normalizeFrozenTxV3 } = require("./frozen-tx-v3");
const { parseSignedTransactionSafeJson } = require("./tx-identity");
const { withVaultIdentityLock } = require("./vault-identity");
const { appendAudit, readAudit } = require("./audit");

// Lazy import avoids the wallet request / submit / recovery module cycle.
const recovery = () => require("./wallet-recovery-v4");
// RC45 R1-03 (RC1-08): the governance truth shared by the finalize/submit gate
// and the attestation exporter, required lazily as store.js requires
// server/src/migrate; evaluated inside the pass for every caller.
const intentRecords = () => require("../../server/src/intent-records");

/* Legacy export only: no option or age releases anything (C1 R2). */
const DEFAULT_STALE_PENDING_MINIMUM_MS = 120_000;
/* D (plan r2 §2.0): a SEEN spender is CONFIRMED at depth >= D DAA (~100 s). */
const SETTLE_DEPTH_DAA = 1000n;
/* Step 7c cap on distinct candidate addresses (L-14); mandatory groups are never dropped. */
const MAX_CANDIDATE_ADDRESSES = 64;
/* Step 9 / A5: the owner-pasted recover evidence is a Safe JSON string of at most 64 KiB (UTF-8). */
const OUT_OF_APP_TRANSACTION_MAX_BYTES = 64 * 1024;
/* RC45 R1-09 (S-03; C9): more than 64 outputs in the pasted transaction is refused at step 0, before any read. */
const OUT_OF_APP_TRANSACTION_MAX_OUTPUTS = 64;
/* RC45 R1-09: step 9 reads outputs[0]'s address, then at most 4 further distinct output addresses. */
const OUT_OF_APP_FURTHER_ADDRESSES = 4;
const HEX64 = /^[0-9a-f]{64}$/;
const RECEIPT_SCHEMA = "policyvault-receipt/v1";
/* RC45 R1-03: the `via` of the history row for a manifest advanced by a governance-refused unsigned primary's txid. */
const GOVERNANCE_REFUSED_VIA = "governance-refused-request-txid";
/* server/src/attestations.js SIGNED_STATES (PolicyVault accepted a signature)
 * plus SUBMISSION_REJECTED: the states a primary is preferred from and a twin
 * or a recorded advancement may be completed from (CR-M10). */
const SIGNED_OR_REJECTED = new Set([
  RequestState.SIGNED, RequestState.FINALIZED, RequestState.PREFLIGHT_VERIFIED, RequestState.SUBMITTING,
  RequestState.SUBMITTED, RequestState.CHAIN_VERIFIED, RequestState.RECONCILIATION_REQUIRED,
  RequestState.TERMINATED_UNKNOWN, RequestState.SUBMISSION_REJECTED
]);

function fail(message, code) {
  const error = new Error(`reconcile-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

const same = (a, b) => recovery().canonicalRecordFingerprint(a ?? null) === recovery().canonicalRecordFingerprint(b ?? null);
/* Exact outpoint identity (writes and contest membership; CR-L10). */
const exactOutpoint = (p, o) => !!p && !!o && same(p, { transactionId: o.transactionId, index: Number(o.index) });
const transitionRecord = (r) => r?.schema === REQUEST_SCHEMA_V4 && r.kind !== "genesis";
const isPending = (config, r) => recovery().isPendingTransitionV4(config, r);
const entryOf = (r, state = r.state) => ({ requestId: r.requestId ?? null, action: r.action ?? null, state: state ?? null, txId: r.txId ?? null });
const pendingEntry = (r) => ({ ...entryOf(r), signerRole: r.signerRole ?? null });
/* RC45 R1-05 (ST-02; C4, K1): the depth of a JUDGED entry (Lref, a SEEN hit,
 * the C-bound step-8 candidate, a step-9 hit) from the node's RAW
 * blockDaaScore. A non-canonical raw value is an observation failure (422
 * RECONCILE_FAILED, nothing written); a score above vDaa gives a negative
 * depth, so below D. Entries that are not judged never reach here (PA-01 r1
 * rule 2). */
function depthOf(vDaa, u) {
  const score = canonicalDaaScore(u.blockDaaScoreRaw);
  if (score === null) {
    const error = new Error(`reconcile-v4: the node's blockDaaScore for ${u.outpoint.transactionId}:${u.outpoint.index} is not a canonical DAA score — nothing was written`);
    error.code = "RECONCILE_FAILED";
    throw observationFailure(error);
  }
  return vDaa - score;
}
const byCreation = (a, b) => {
  const x = [String(a.createdAt ?? ""), String(a.requestId ?? "")], y = [String(b.createdAt ?? ""), String(b.requestId ?? "")];
  return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0;
};

/* Settlement lists strictly (a corrupt record fails the pass, never hides
 * evidence), sorted by (createdAt, requestId). Guards stay non-strict. */
async function listSettlementRequests(config, vaultId) {
  const all = await getStore(config).listValues(Categories.REQUEST, { strict: true });
  return all.filter((r) => r && r.vaultId === vaultId && r.schema === REQUEST_SCHEMA_V4).sort(byCreation);
}

/* validateIdentity by call site (plan r2 §2.0, CR-M2, CR2-L3): an environment
 * error aborts the pass with 422 and nothing written (after a restore in the
 * same pass, the message names the restore: afterWrites, RC45 R1-14); any
 * other throw excludes only that record (null). */
function validated(config, r) {
  try {
    return recovery().validateIdentity(config, r);
  } catch (error) {
    if (error?.environmentError === true) fail(`${error.message} — nothing was written`, "RECONCILE_FAILED");
    return null;
  }
}

/* RC45 F7 (plan r2 §2.6 step 4, CR2-L10): a failed or malformed node answer is
 * an observation failure. It is marked `observationError`, so request-scoped
 * recovery answers it PROTECTED_UNRESOLVED with no further write while store
 * and write errors propagate; the Verify route still answers it 422. A
 * non-Error or non-extensible throw is carried in a new Error with the same
 * message, so it is still marked. */
function observationFailure(error) {
  const marked = error instanceof Error && Object.isExtensible(error) ? error : new Error(String(error?.message ?? error));
  marked.observationError = true;
  return marked;
}

/* Chain reads of one pass: the virtual DAA score once, before the reads it
 * judges; every address at most once; a failed read is remembered. */
function observer(rpc) {
  const reads = new Map();
  let vDaa = null, failed = false;
  const read = async (address) => {
    if (!reads.has(address)) reads.set(address, getAddressUtxos(rpc, address).then((entries) => ({ entries }), (error) => ({ error: observationFailure(error) })));
    const out = await reads.get(address);
    if (out.error) throw out.error;
    return out.entries;
  };
  return {
    async virtualDaaScore() {
      if (vDaa === null) {
        try { vDaa = await getVirtualDaaScore(rpc); } catch (error) { throw observationFailure(error); }
      }
      return vDaa;
    },
    read,
    async tryRead(address) { try { return await read(address); } catch { failed = true; return null; } },
    async peek(address) { if (!reads.has(address)) return null; const out = await reads.get(address); return out.entries ?? null; },
    get failed() { return failed; }
  };
}

/* The frozen outputs of a record as read specs, classed successor (covenant
 * output), signer change (the signer's address), recipient. No compile. */
function outputSpecs(config, r) {
  let frozen;
  try { frozen = normalizeFrozenTxV3(r.build?.frozen); } catch { return []; }
  const specs = [];
  frozen.outputs.forEach((o, index) => {
    let address;
    try { address = frozenScriptAddress(config, o.scriptPublicKey); } catch { return; }
    specs.push({ address, index, value: o.value, scriptHex: o.scriptPublicKey.scriptHex, version: o.scriptPublicKey.version,
      covenantId: o.covenant?.covenantId ?? null, cls: o.covenant ? 0 : address === r.signerAddress ? 1 : 2 });
  });
  return specs;
}
/* SEEN: the frozen output observed exactly at txId:index with its value, script bytes, version and covenant binding. */
const observedAs = (u, txId, s) => u.outpoint.transactionId === txId && u.outpoint.index === s.index && u.amount === s.value &&
  u.scriptPublicKeyHex === s.scriptHex && u.scriptPublicKeyVersion === s.version && (u.covenantId ?? null) === s.covenantId;

/* Step 7a-c: the requests ON `outpoint` (any state, hex txid), grouped by txid.
 * MANDATORY groups (owner break-glass, a PENDING member, the claim holder) are
 * never dropped; OPTIONAL groups are taken newest first while the distinct
 * addresses stay <= 64; the rest are skipped and counted. */
async function candidateGroups(config, reqs, outpoint, { exceptTxId = null } = {}) {
  const claim = await getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(outpoint));
  const byTxId = new Map();
  for (const r of reqs) {
    if (!transitionRecord(r) || !HEX64.test(r.txId ?? "") || r.txId === exceptTxId || !recovery().onOutpoint(r, outpoint)) continue;
    const g = byTxId.get(r.txId) ?? { txId: r.txId, members: [], specs: new Map(), mandatory: false, newest: r };
    g.members.push(r); g.newest = r;
    for (const s of outputSpecs(config, r)) g.specs.set([s.address, s.index, s.value, s.scriptHex, s.version, s.covenantId].join("|"), s);
    if (!g.mandatory && (isBreakGlassV4(r) || r.txId === claim?.txId || await isPending(config, r))) g.mandatory = true;
    byTxId.set(r.txId, g);
  }
  const groups = [...byTxId.values()], kept = groups.filter((g) => g.mandatory), addresses = new Set();
  for (const g of kept) for (const s of g.specs.values()) addresses.add(s.address);
  let skipped = 0, open = true;
  for (const g of groups.filter((x) => !x.mandatory).sort((a, b) => byCreation(b.newest, a.newest))) {
    if (open) {
      const union = new Set(addresses);
      for (const s of g.specs.values()) union.add(s.address);
      if (union.size <= MAX_CANDIDATE_ADDRESSES) { kept.push(g); for (const a of union) addresses.add(a); continue; }
      open = false;
    }
    skipped += 1;
  }
  return { kept, skipped };
}
/* Step 7d: read by class (successor, signer change, recipient) and stop after
 * the first class with a positive; SEEN is decided in memory for every group.
 * Returns txId -> the observed outputs. */
async function observeGroups(chain, groups) {
  const seen = new Map();
  for (const cls of [0, 1, 2]) {
    for (const g of groups) for (const s of g.specs.values()) if (s.cls === cls) await chain.tryRead(s.address);
    for (const g of groups) {
      const hits = [];
      for (const s of g.specs.values()) {
        const u = (await chain.peek(s.address))?.find((entry) => observedAs(entry, g.txId, s));
        if (u) hits.push(u);
      }
      if (hits.length) seen.set(g.txId, hits);
    }
    if (seen.size) break;
  }
  return seen;
}

/* ---------------- settlement writes (plan r2 §4 orders) ---------------- */

async function releaseOwnSubmissionClaim(config, txId) {
  const store = getStore(config);
  if (await store.read(Categories.SUBMISSION_CLAIM, txId)) await store.remove(Categories.SUBMISSION_CLAIM, txId);
}
/* Relabels change `state` only, on the current record of the same transaction
 * (H-44); a journaled record is never written (L-15). */
async function relabel(config, r, state) {
  const fresh = await loadRequest(config, r.requestId);
  if (!fresh || fresh.txId !== r.txId || fresh.transitionRecovery) return false;
  if (fresh.state !== state) await saveRequest(config, { ...fresh, state });
  return true;
}
/* The create-only completion receipt; an existing one of any shape is kept
 * (H-40). completePositive writes it first (RC45 R1-06 C3). */
async function ensureReceipt(config, r, e) {
  const store = getStore(config), terminal = e.kind === "recover";
  if (await store.read(Categories.RECEIPT, r.txId)) return;
  await store.createExclusive(Categories.RECEIPT, r.txId, { schema: RECEIPT_SCHEMA, txId: r.txId, vaultId: r.vaultId, action: r.action,
    proof: { requestId: r.requestId, successorOutpoint: terminal ? null : `${r.txId}:${e.index}`, value: e.valueSompi, reconciled: true },
    verifiedAt: new Date().toISOString() });
}
/* Steps 3-6 of completePositive (also finishRecordedV4 and settleOneHop): the
 * create-only receipt (kept when it exists), the idempotent
 * reconciled_advanced row, the own claims (rule R), the reservation, and
 * CHAIN_VERIFIED last. */
async function completeRecord(config, r, e) {
  const terminal = e.kind === "recover";
  await ensureReceipt(config, r, e);
  const rows = await readAudit(config, { vaultId: r.vaultId, txId: r.txId, limit: 1000 });
  if (!rows.some((row) => row.action === "reconciled_advanced" && row.via === "reconcile" && row.txId === r.txId)) {
    await appendAudit(config, { vaultId: r.vaultId, action: "reconciled_advanced", actor: "system", via: "reconcile", requestId: r.requestId,
      txId: r.txId, result: "CHAIN_VERIFIED", oldStateId: r.predecessorStateId, newStateId: terminal ? null : r.successorStateId });
  }
  await releaseOwnTransitionClaimV4(config, { outpoint: r.predecessorOutpoint, txId: r.txId });
  await releaseOwnSubmissionClaim(config, r.txId);
  await releaseReservationForRequest(config, r);
  await relabel(config, r, RequestState.CHAIN_VERIFIED);
}
/* RC45 R1-03 (F-01, C1): a primary outside SIGNED_OR_REJECTED that the
 * governance gate refuses (governanceRefusalFor non-null on the manifest record
 * it created: the exporter's evidence, server/src/attestations.js) is never
 * relabelled and no receipt names it, so it keeps its REFUSED record.
 * Read-only; an unknown proposal or terminal-claim schema (422) or a manifest
 * record integrity alarm throws before any write. Signed primaries are not read
 * (their completion is unchanged). */
async function governanceRefusedUnsigned(config, r) {
  if (SIGNED_OR_REJECTED.has(r.state)) return false;
  const ir = intentRecords();
  const record = typeof r.manifestHash === "string" ? await ir.loadManifestRecord(config, r.manifestHash) : null;
  return (await ir.governanceRefusalFor(config, r, record)) !== null;
}
/* RC45 R1-03: the idempotent history row of a manifest advanced by such a
 * primary's txid. It names the txid only: no receipt, no relabel, no requestId. */
async function governanceRefusedAdvanceRow(config, r, e) {
  const rows = await readAudit(config, { vaultId: r.vaultId, txId: r.txId, limit: 1000 });
  if (!rows.some((row) => row.action === "reconciled_advanced" && row.via === GOVERNANCE_REFUSED_VIA && row.txId === r.txId)) {
    await appendAudit(config, { vaultId: r.vaultId, action: "reconciled_advanced", actor: "system", via: GOVERNANCE_REFUSED_VIA, txId: r.txId,
      result: "CHAIN_VERIFIED", oldStateId: r.predecessorStateId, newStateId: e.kind === "recover" ? null : r.successorStateId });
  }
}
/* twinComplete (H-39, CR-M10): a journal-free, identity-valid same-txid twin in
 * a signed state (or SUBMISSION_REJECTED) is CHAIN_VERIFIED by the shared
 * receipt; BUILT, AWAITING_APPROVALS and pre-signature closed twins stay as
 * they are (a governance ladder refusal must not be dropped). */
async function twinComplete(config, t, settled) {
  const r = t.r;
  if (r.transitionRecovery || !SIGNED_OR_REJECTED.has(r.state) || r.state === RequestState.CHAIN_VERIFIED) return;
  if (!(await relabel(config, r, RequestState.CHAIN_VERIFIED))) return;
  await releaseReservationForRequest(config, r);
  settled.push(entryOf(r, RequestState.CHAIN_VERIFIED));
}
/* settleLoser (CR-M2, CR-L10, CR-L13, CR-L4): only for a CONFIRMED winner (the
 * caller holds depth >= D) with another txid that spends the loser's
 * predecessor exactly (`winner.spent`: a hosted winner's frozen input 0, a
 * pasted recover's input equal to L), and a journal-free, identity-valid loser
 * unchanged since it was validated. Order: the idempotent transition_superseded
 * row, STALE, the loser's own claims (rule R), then its reservation. */
const hostedWinner = (W) => ({ txId: W.r.txId, spent: W.v.frozen.inputs[0].previousOutpoint });
async function settleLoser(config, loser, winner, depth, settled) {
  const r = loser.r;
  if (r.txId === winner.txId || r.transitionRecovery || !same(winner.spent, r.predecessorOutpoint)) return;
  const fresh = await loadRequest(config, r.requestId);
  if (!fresh || !same(fresh, r)) return;
  const rows = await readAudit(config, { vaultId: r.vaultId, txId: r.txId, limit: 1000 });
  if (!rows.some((row) => row.action === "transition_superseded" && row.requestId === r.requestId && row.winnerTxId === winner.txId)) {
    await appendAudit(config, { vaultId: r.vaultId, action: "transition_superseded", actor: "system", requestId: r.requestId,
      txId: r.txId, winnerTxId: winner.txId, depth: String(depth) });
  }
  await saveRequest(config, { ...fresh, state: RequestState.STALE });
  await releaseOwnTransitionClaimV4(config, { outpoint: r.predecessorOutpoint, txId: r.txId });
  await releaseOwnSubmissionClaim(config, r.txId);
  await releaseReservationForRequest(config, r);
  settled.push(entryOf(r, RequestState.STALE));
}

/* The recorded live state as the pass's base. */
function liveBase(m) {
  const l = m.live;
  return { state: l.state, stateId: l.stateId, outpoint: l.outpoint, value: l.outpointValue, scriptSha256: l.scriptSha256, covenantId: l.covenantId };
}
function baseToJson(base) {
  return { state: stateToJsonV4(base.state), stateId: base.stateId, outpoint: { transactionId: base.outpoint.transactionId, index: Number(base.outpoint.index) },
    outpointValue: String(base.value), scriptSha256: base.scriptSha256, covenantId: base.covenantId };
}
const statusOf = (state) => (state.paused === 1n ? VaultStatus.PAUSED : VaultStatus.ACTIVE);
/*
 * lastRecordedLive (TERMINATED_UNKNOWN only; CR-L9, CR2-L4): the successor
 * recorded by the lastTransition's request W1 (its txid and successor state
 * id), or, only when there is no lastTransition, the genesis request of
 * m.creationTxId. Anything else is null: UNKNOWN{no recorded live state}.
 */
function lastRecordedLive(m, reqs) {
  const identity = (state) => computeStateIdV4({ networkId: m.networkId, template: m.template, state, contractVersion: m.contractVersion });
  const t = m.lastTransition;
  if (t) {
    if (!t.newOutpoint || !t.newStateId) return null;
    for (const r of reqs) {
      if (!transitionRecord(r) || r.txId !== t.txId || r.successorStateId !== t.newStateId || !HEX64.test(r.covenantId ?? "")) continue;
      try {
        const state = normalizeStateV4(r.build.successorState);
        if (identity(state) !== t.newStateId || !HEX64.test(r.build.successorScriptSha256 ?? "")) continue;
        return { state, stateId: t.newStateId, outpoint: t.newOutpoint, value: state.protectedValue + state.feeReserve,
          scriptSha256: r.build.successorScriptSha256, covenantId: r.covenantId };
      } catch { continue; }
    }
    return null;
  }
  if (!m.creationTxId) return null;
  for (const r of reqs) {
    if (r.kind !== "genesis" || r.txId !== m.creationTxId || r.contractVersion !== m.contractVersion || !same(r.template, m.template) ||
        !HEX64.test(r.covenantId ?? "") || !HEX64.test(r.scriptSha256 ?? "") || !Number.isSafeInteger(r.vaultOutputIndex) || r.vaultOutputIndex < 0) continue;
    try {
      const state = normalizeStateV4(r.initialState);
      return { state, stateId: identity(state), outpoint: { transactionId: m.creationTxId, index: r.vaultOutputIndex },
        value: state.protectedValue + state.feeReserve, scriptSha256: r.scriptSha256, covenantId: r.covenantId };
    } catch { continue; }
  }
  return null;
}
/* restore: one manifest write (live = base, status by paused, the registry
 * root re-checked by the loader) plus reconciled_advanced {via: "restored"}. */
async function restore(config, m, base) {
  const restored = await persistManifestV4(config, { ...manifestToJson(m), status: statusOf(base.state), live: baseToJson(base) });
  await appendAudit(config, { vaultId: m.vaultId, action: "reconciled_advanced", actor: "system", via: "restored", result: "CHAIN_VERIFIED", newStateId: base.stateId });
  return restored;
}

/*
 * RC45 R1-06 (ST-03; C2): the receipt-matching finish, read-only. Exactly: a
 * journal-free record in SIGNED_OR_REJECTED and not CHAIN_VERIFIED whose own
 * txid's receipt receiptMatches it (proof.requestId, the expected outpoint and
 * value) and whose identity is valid is finished CHAIN_VERIFIED from that
 * recorded proof, with no node call, in any hop position of the recorded
 * history. A record ON the recorded live outpoint is not yet a hop (the
 * receipt-first crash window): step 7 re-enters and advances it (C3). Its
 * same-txid twins finish only through twinComplete (CR-M10: unsigned twins
 * stay); journaled records are never written (L-15); an unsigned record keeps
 * its label (the K5 residual). `taken` names the records the caller already
 * finishes or supersedes. Validated before the caller's first write; returns
 * [{r, v, twins}].
 */
async function receiptFinishable(config, m, reqs, taken = []) {
  const store = getStore(config), skip = new Set(taken), live = m.live?.outpoint ?? null, list = [];
  const open = (r) => transitionRecord(r) && !r.transitionRecovery && SIGNED_OR_REJECTED.has(r.state) && r.state !== RequestState.CHAIN_VERIFIED && !skip.has(r.requestId);
  for (const r of reqs) {
    if (!open(r) || typeof r.requestId !== "string" || !HEX64.test(r.txId ?? "") || (live && recovery().onOutpoint(r, live))) continue;
    const receipt = await store.read(Categories.RECEIPT, r.txId);
    if (receipt?.proof?.requestId !== r.requestId) continue;
    const v = validated(config, r);
    if (!v || !recovery().ownReceiptMatches(receipt, r, v.expected)) continue;
    skip.add(r.requestId);
    const twins = [];
    for (const x of reqs) {
      if (x.txId !== r.txId || !open(x)) continue;
      const tv = validated(config, x);
      if (tv) { twins.push({ r: x, v: tv }); skip.add(x.requestId); }
    }
    list.push({ r, v, twins });
  }
  return list;
}
/* RC45 R1-06 (C2): steps 3-6 for each receipt-matching record (its receipt is
 * kept, H-40), then its twins through twinComplete. */
async function finishByReceipt(config, list, settled) {
  for (const { r, v, twins } of list) {
    await completeRecord(config, r, v.expected);
    settled.push(entryOf(r, RequestState.CHAIN_VERIFIED));
    for (const t of twins) await twinComplete(config, t, settled);
  }
}
/*
 * finishRecordedV4 (step 3 and request-scoped recovery; CR-M3, CR-L2): each
 * journal-free PENDING record in a signed state (or SUBMISSION_REJECTED) whose
 * txid is the manifest's lastTransition and whose exact advancement the
 * manifest records gets steps 3-6, with no node call; then every other record
 * its own receipt finishes (RC45 R1-06 C2). Every record is validated before
 * the first write. Returns true when anything was written.
 */
async function finishRecordedV4(config, m, reqs, settled = []) {
  const t = m.lastTransition, finish = [];
  if (t) {
    for (const r of reqs) {
      if (!transitionRecord(r) || r.txId !== t.txId || r.transitionRecovery || !SIGNED_OR_REJECTED.has(r.state) || !(await isPending(config, r))) continue;
      const v = validated(config, r);
      if (v && recovery().exactAdvanced(m, r, v.expected)) finish.push({ r, v });
    }
  }
  const byReceipt = await receiptFinishable(config, m, reqs, finish.map((x) => x.r.requestId));
  for (const { r, v } of finish) {
    await completeRecord(config, r, v.expected);
    settled.push(entryOf(r, RequestState.CHAIN_VERIFIED));
  }
  await finishByReceipt(config, byReceipt, settled);
  return finish.length > 0 || byReceipt.length > 0;
}
/*
 * settleOneHop (H-25, CR-M10): the live L is the recorded advancement's
 * successor at depth >= D. Its W1-txid records exactly on the old outpoint that
 * lack CHAIN_VERIFIED + receipt get steps 3-6 (exact advancement required;
 * signed or SUBMISSION_REJECTED only, so an unsigned W1 keeps its label, R1-03);
 * the other journal-free PENDING records exactly on the old outpoint are
 * superseded by W1; then every other record its own receipt finishes (RC45
 * R1-06 C2, any hop position). Validated before the first write; nothing to do
 * reads no record's bytes.
 */
async function settleOneHop(config, m, reqs, L, depth, settled) {
  const t = m.lastTransition;
  if (!t || !t.newOutpoint || !exactOutpoint(t.newOutpoint, L) || depth < SETTLE_DEPTH_DAA) return false;
  const hop = await lastHop(config, m, reqs, t);
  const byReceipt = await receiptFinishable(config, m, reqs, [...hop.finish, ...hop.losers].map((x) => x.r.requestId));
  for (const { r, v } of hop.finish) {
    await completeRecord(config, r, v.expected);
    settled.push(entryOf(r, RequestState.CHAIN_VERIFIED));
  }
  for (const loser of hop.losers) await settleLoser(config, loser, hop.winner, depth, settled);
  await finishByReceipt(config, byReceipt, settled);
  return hop.finish.length > 0 || hop.losers.length > 0 || byReceipt.length > 0;
}
/* settleOneHop's last hop, read-only: the W1 records to finish, the validated
 * losers and the winner they are superseded by. */
async function lastHop(config, m, reqs, t) {
  const none = { finish: [], losers: [], winner: null };
  const w1 = reqs.filter((r) => transitionRecord(r) && r.txId === t.txId && exactOutpoint(r.predecessorOutpoint, t.oldOutpoint));
  if (!w1.length) return none;
  const receipt = await getStore(config).read(Categories.RECEIPT, t.txId);
  const receipted = (r) => receipt?.schema === RECEIPT_SCHEMA && receipt.txId === r.txId && receipt.vaultId === r.vaultId && receipt.action === r.action;
  const unfinished = w1.filter((r) => !r.transitionRecovery && SIGNED_OR_REJECTED.has(r.state) && !(r.state === RequestState.CHAIN_VERIFIED && receipted(r)));
  const candidates = [];
  for (const r of reqs) {
    if (transitionRecord(r) && !r.transitionRecovery && r.txId !== t.txId && exactOutpoint(r.predecessorOutpoint, t.oldOutpoint) && await isPending(config, r)) candidates.push(r);
  }
  if (!unfinished.length && !candidates.length) return none;
  const winners = w1.map((r) => ({ r, v: validated(config, r) })).filter((x) => x.v);
  if (!winners.length) return none;
  return { finish: winners.filter((x) => unfinished.includes(x.r) && recovery().exactAdvanced(m, x.r, x.v.expected)),
    losers: candidates.map((r) => ({ r, v: validated(config, r) })).filter((x) => x.v), winner: hostedWinner(winners[0]) };
}
/*
 * releaseEstablishedLeftover (CR-M4, CR-I1; finishes wallet-submit-v4's
 * REJECTED branch, H-06): the claim on L is released only when at least one
 * record names its txid and every such record is journal-free and an
 * established rejection. An orphan claim stays byte-identical.
 */
async function releaseEstablishedLeftover(config, m, reqs, L, settled) {
  const claim = await getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(L));
  if (!claim || !HEX64.test(claim.txId ?? "") || claim.vaultId !== m.vaultId) return false;
  const named = reqs.filter((r) => r.txId === claim.txId);
  if (!named.length || !named.every((r) => !r.transitionRecovery && recordedNegativeIsEstablished(r))) return false;
  await releaseOwnTransitionClaimV4(config, { outpoint: L, txId: claim.txId });
  await releaseOwnSubmissionClaim(config, claim.txId);
  await appendAudit(config, { vaultId: m.vaultId, action: "submission_rejected_claims_released", actor: "system", via: "reconcile", requestId: named[0].requestId,
    txId: claim.txId, result: "REJECTED_BY_NODE", oldStateId: named[0].predecessorStateId, detail: "an established rejection's leftover claims released by Verify" });
  for (const r of named) await releaseReservationForRequest(config, r);
  for (const r of named) settled.push(entryOf(r));
  return true;
}

/* ---------------- the pass ---------------- */

const contradiction = (vaultId, reason) => ({ status: "CHAIN_CONTRADICTION", vaultId, reason: `${reason}; nothing was written` });
const belowDepth = (vaultId, depth, extra) => ({ status: "CLAIM_PENDING", vaultId, ...extra, depth: String(depth), required: String(SETTLE_DEPTH_DAA) });

/* Step 0 (R2, LEAD5-PRECEDENCE-01): a process that is not on an operational
 * network, or whose configured network differs from the manifest's stamp, is
 * refused before it reasons about this vault's request history. Pure: no node
 * contact, no write. */
async function loadVerifiedManifest(config, vaultId) {
  const manifest = await loadManifestV4(config, vaultId); // loader enforces registry root-equality
  if (!manifest) fail(`no v0.4 manifest for vault ${vaultId}`);
  resolveV4Abi(manifest.contractVersion); // accepts the v0.4 family; fails closed otherwise
  assertOperationalNetwork(config); // Gate R: testnet-10 or unlocked mainnet
  if (manifest.networkId !== config.networkId) fail(`manifest network ${manifest.networkId} != configured ${config.networkId} — refusing`);
  return manifest;
}

/* A5 / step 9 shape rule (pure): absent (undefined), or a string of at most
 * 64 KiB whose transaction carries at most 64 outputs (RC45 R1-09); anything
 * else is refused before any read or write. A paste the engine does not read
 * is not refused here: it keeps step 9's mismatch path. The hosted route
 * applies the same rule after the owner-access gate (CR-L6, RC1-11). */
function assertOutOfAppTransactionShape(config, outOfAppTransaction) {
  if (outOfAppTransaction === undefined) return;
  if (typeof outOfAppTransaction !== "string" || Buffer.byteLength(outOfAppTransaction, "utf8") > OUT_OF_APP_TRANSACTION_MAX_BYTES) {
    fail(`outOfAppTransaction must be a Safe JSON string of at most ${OUT_OF_APP_TRANSACTION_MAX_BYTES} bytes — nothing was read or written`, "BAD_FORMAT");
  }
  const outputs = pastedOutputCount(config, outOfAppTransaction);
  if (outputs !== null && outputs > OUT_OF_APP_TRANSACTION_MAX_OUTPUTS) {
    fail(`outOfAppTransaction carries ${outputs} outputs; at most ${OUT_OF_APP_TRANSACTION_MAX_OUTPUTS} are accepted — nothing was read or written`, "BAD_FORMAT");
  }
}
/* The number of outputs of the pasted transaction as step 9's parser reads it
 * (parseSignedTransactionSafeJson), or null when it does not read it. */
function pastedOutputCount(config, outOfAppTransaction) {
  try { return parseSignedTransactionSafeJson(config, outOfAppTransaction).outputs.length; } catch { return null; }
}

/*
 * Verify one v0.4 vault against chain truth. Returns a status object. Only
 * `rpc` and the optional owner-pasted recover evidence `outOfAppTransaction`
 * (step 9; verified against the chain, grants no authority) are read from the
 * options; legacy stalePendingMinimumMs / allowClaimRelease options are
 * ignored (they cannot authorize anything).
 */
async function reconcileVaultV4(config, vaultId, { rpc, outOfAppTransaction } = {}) {
  assertOutOfAppTransactionShape(config, outOfAppTransaction);
  const manifest = await loadVerifiedManifest(config, vaultId);
  return withVaultIdentityLock(manifest.vaultId, () => reconcileVaultV4Unlocked(config, vaultId, { rpc, outOfAppTransaction }));
}

/* The pass itself, for a caller that already holds the vault identity lock
 * (process-local and not re-entrant: request-scoped recovery). */
async function reconcileVaultV4Unlocked(config, vaultId, { rpc: providedRpc, outOfAppTransaction } = {}) {
  assertOutOfAppTransactionShape(config, outOfAppTransaction);
  const m = await loadVerifiedManifest(config, vaultId);
  let reqs = await listSettlementRequests(config, m.vaultId);
  const settled = [];

  // Step 3: a closed vault. Finishing its recorded advancement needs no node call.
  if (!m.live && m.status !== VaultStatus.TERMINATED_UNKNOWN) {
    if (m.status === VaultStatus.RECOVERED && await finishRecordedV4(config, m, reqs, settled)) reqs = await listSettlementRequests(config, m.vaultId);
    const pending = [];
    for (const r of reqs) if (await isPending(config, r)) pending.push(r);
    const recordedVaultClosed = m.status === VaultStatus.RECOVERED && m.live === null;
    if (pending.length) {
      return { status: "REQUEST_RECOVERY_REQUIRED", vaultId, requestId: pending[0].requestId, pending: pending.map(pendingEntry),
        vaultStatus: m.status, recordedVaultClosed,
        reason: recordedVaultClosed
          ? "the recorded vault is closed; historical request evidence remains unresolved and protected; no new recovery or transaction is authorized"
          : "an unresolved transition requires request-scoped observation and protection", ...(settled.length ? { settled } : {}) };
    }
    return { status: "TERMINAL", vaultStatus: m.status, ...(settled.length ? { settled } : {}) };
  }

  // Step 4: the base. TERMINATED_UNKNOWN (RC44 case E) uses the last recorded live state.
  const base = m.live ? liveBase(m) : lastRecordedLive(m, reqs);
  if (!base) return { status: "UNKNOWN", vaultId, reason: "no recorded live state", unchecked: 0 };

  // Step 5.
  const owned = !providedRpc;
  const { rpc } = owned ? await connectVerified(config) : { rpc: providedRpc };
  const ctx = { vaultId, m, base, reqs, settled, chain: observer(rpc), outOfAppTransaction, restored: false };
  try {
    return await settleFromChain(config, ctx);
  } catch (error) {
    throw afterWrites(ctx, error);
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/*
 * RC45 R1-14 (O2; PA-R1-02, C2): the pass's context records whether it has
 * written (`restored`, set by settleLive). The restore is the only durable
 * write that can come before an environment failure in the same pass: after
 * it come only settleOneHop's validated() calls, and settleOneHop validates
 * every record before its first write. Such a failure keeps 422
 * RECONCILE_FAILED, its cause and the pass's writes; only its "nothing was
 * written" is replaced by what was written. A failure before any write keeps
 * its text.
 */
const NOTHING_WRITTEN_TAIL = " — nothing was written";
function afterWrites(ctx, error) {
  if (!ctx.restored || error?.code !== "RECONCILE_FAILED" || typeof error.message !== "string" || !error.message.endsWith(NOTHING_WRITTEN_TAIL)) return error;
  error.message = `${error.message.slice(0, -NOTHING_WRITTEN_TAIL.length)} — the TERMINATED_UNKNOWN vault was restored at depth to its recorded live outpoint before the failure (one manifest write and one reconciled_advanced history row); nothing else was written`;
  return error;
}

async function settleFromChain(config, ctx) {
  const { vaultId, m, base, reqs, settled, chain } = ctx, L = base.outpoint;
  // Step 6: every Verify reads the recorded outpoint first (reorg rule, -05).
  const template = { owner: m.template.owner, vaultId: m.vaultId };
  const current = successorAddressAndScript(config, template, stateToJsonV4(base.state), m.contractVersion);
  if (current.scriptSha256 !== base.scriptSha256) fail("compiled recorded state does not match its recorded script hash — failing closed");
  const vDaa = await chain.virtualDaaScore();
  const lref = (await chain.read(current.address)).find((u) => u.outpoint.transactionId === L.transactionId && u.outpoint.index === Number(L.index) &&
    u.amount === base.value && u.covenantId === base.covenantId) ?? null;
  if (lref) return settleLive(config, ctx, depthOf(vDaa, lref));

  // Step 7: L is spent. Candidate groups ON L, read by class under the cap.
  const { kept, skipped } = await candidateGroups(config, reqs, L);
  const seen = await observeGroups(chain, kept);
  const spenders = [];
  for (const g of kept) {
    if (!seen.has(g.txId)) continue;
    const valid = [];
    for (const r of g.members) { const v = validated(config, r); if (v) valid.push({ r, v }); }
    if (!valid.length) continue;
    const primary = valid.find((x) => SIGNED_OR_REJECTED.has(x.r.state)) ?? valid[0];
    if (primary.r.transitionRecovery) {
      // Journaled RC42/RC44 history is never written (L-15).
      return { status: "REQUEST_RECOVERY_REQUIRED", vaultId, requestId: primary.r.requestId, pending: [pendingEntry(primary.r)], vaultStatus: m.status,
        recordedVaultClosed: false, reason: "a journaled historical request spent the recorded outpoint; Verify never writes journaled history" };
    }
    const depth = seen.get(g.txId).reduce((min, u) => { const d = depthOf(vDaa, u); return min === null || d < min ? d : min; }, null);
    spenders.push({ primary, twins: valid.filter((x) => x !== primary), depth });
  }
  if (spenders.length > 1) return contradiction(vaultId, "more than one recorded transaction is observed spending the recorded outpoint");
  if (spenders.length === 1) {
    const { primary, twins, depth } = spenders[0];
    if (depth < SETTLE_DEPTH_DAA) {
      return belowDepth(vaultId, depth, { txId: primary.r.txId, requestId: primary.r.requestId,
        reason: "a recorded transaction spending the recorded outpoint is observed below the settlement depth; nothing was written" });
    }
    const losers = [];
    for (const r of reqs) {
      if (!transitionRecord(r) || r.txId === primary.r.txId || r.transitionRecovery || !exactOutpoint(r.predecessorOutpoint, L) || !(await isPending(config, r))) continue;
      const v = validated(config, r);
      if (v) losers.push({ r, v });
    }
    return completePositive(config, ctx, primary, twins, losers, depth);
  }
  if (chain.failed) fail("nothing recorded is observed spending the recorded outpoint and a chain read failed — nothing was written", "RECONCILE_FAILED");

  // Step 8: adoption of an out-of-app pause / unpause (§2.5(1)).
  const adopted = await adoptOutOfApp(config, ctx, current, vDaa);
  if (adopted) return adopted;

  // Step 9: owner-pasted recover evidence (§2.5(3)); a mismatch settles nothing and the pass continues.
  const evidence = await recoverEvidence(config, ctx, vDaa);
  if (evidence?.result) return evidence.result;

  // Step 10: the recorded old outpoint live again, or spent by another recorded txid.
  const ancestor = await ancestorContradiction(config, ctx);
  if (ancestor.contradiction) return contradiction(vaultId, ancestor.contradiction);
  if (chain.failed) fail("the recorded outpoint is spent and a chain read failed — nothing was written", "RECONCILE_FAILED");

  // Step 11 (replaces RC44 case E): absence writes nothing. The paste's unread output addresses count as unchecked (R1-09).
  const pasted = evidence ? `; the pasted transaction settles nothing: ${evidence.mismatch}` : "";
  return { status: "UNKNOWN", vaultId, reason: `the recorded outpoint is spent and no known spender was seen${pasted}`,
    unchecked: skipped + ancestor.unchecked + (evidence?.unchecked ?? 0), ...(settled.length ? { settled } : {}) };
}

/* Step 6, L live: restore (TERMINATED_UNKNOWN; recorded in the pass's context,
 * RC45 R1-14), settleOneHop, the established leftover, then the answer. */
async function settleLive(config, ctx, depth) {
  const { vaultId, base, settled } = ctx, L = base.outpoint;
  let m = ctx.m, reqs = ctx.reqs;
  if (!m.live) {
    if (depth < SETTLE_DEPTH_DAA) {
      return belowDepth(vaultId, depth, { reason: "the recorded live outpoint is observed below the settlement depth; the vault is restored at depth; nothing was written" });
    }
    m = await restore(config, m, base);
    ctx.restored = true;
  }
  if (await settleOneHop(config, m, reqs, L, depth, settled)) reqs = await listSettlementRequests(config, m.vaultId);
  if (await releaseEstablishedLeftover(config, m, reqs, L, settled)) reqs = await listSettlementRequests(config, m.vaultId);
  const pending = [];
  for (const r of reqs) if (recovery().onOutpoint(r, L) && await isPending(config, r)) pending.push(r);
  if (pending.length) {
    return { status: "REQUEST_RECOVERY_REQUIRED", vaultId, requestId: pending[0].requestId, pending: pending.map(pendingEntry), vaultStatus: m.status,
      recordedVaultClosed: false, reason: "signed work on the recorded outpoint may still execute and blocks other actions", ...(settled.length ? { settled } : {}) };
  }
  const claim = await getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(L));
  if (claim) {
    return { status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId ?? null,
      reason: "the recorded outpoint is live and claimed; absence does not establish rejection; the claim is kept", ...(settled.length ? { settled } : {}) };
  }
  return { status: "CONSISTENT", vaultId, settled };
}

/*
 * completePositive (journal-free primary r, CONFIRMED at depth >= D): the
 * winner's create-only receipt is the first durable write of the completion
 * (RC45 R1-06 C3; an existing receipt of any shape is kept, H-40), so a crash
 * before the manifest re-enters this branch while the finalize/submit receipt
 * guard refuses the winner. A terminal winner then settles its losers first,
 * so a crash before the manifest re-enters this branch (CR-M3); then the
 * manifest (the TERMINATED_UNKNOWN base is made live first; an exact recorded
 * advancement is skipped; anything else is CHAIN_CONTRADICTION before any
 * write), steps 3-6, the twins, and a non-terminal winner's losers. A
 * governance-refused unsigned primary (RC45 R1-03, decided before the first
 * write) gets no receipt; it gets the manifest advance, the losers and the
 * governance-refused-request-txid history row instead of steps 3-6, and the
 * answer omits requestId (RC1-09); its twins are unsigned too, so none is
 * completed.
 */
async function completePositive(config, ctx, W, twins, losers, depth) {
  const { vaultId, m, base, settled } = ctx, r = W.r, e = W.v.expected, terminal = e.kind === "recover";
  const already = recovery().exactAdvanced(m, r, e);
  let from = null;
  if (!already) {
    if (!exactOutpoint(r.predecessorOutpoint, base.outpoint)) return contradiction(vaultId, "the observed spender does not spend the recorded live outpoint");
    from = m.live ? m : normalizeManifestV4({ ...manifestToJson(m), status: statusOf(base.state), live: baseToJson(base) });
  }
  const refused = await governanceRefusedUnsigned(config, r);
  if (!refused) await ensureReceipt(config, r, e);
  if (terminal) for (const loser of losers) await settleLoser(config, loser, hostedWinner(W), depth, settled);
  if (!already) await advanceManifestAndRegistryV4(config, from, r, e);
  if (refused) await governanceRefusedAdvanceRow(config, r, e);
  else await completeRecord(config, r, e);
  for (const t of twins) await twinComplete(config, t, settled);
  if (!terminal) for (const loser of losers) await settleLoser(config, loser, hostedWinner(W), depth, settled);
  return { status: "ADVANCED", vaultId, to: terminal ? "RECOVERED" : r.action, txId: r.txId, ...(refused ? {} : { requestId: r.requestId }),
    ...(terminal ? {} : { stateId: e.stateId }), settled };
}

/*
 * Step 8 (§2.5(1); CR-L8 as amended by plan amendment PA-01 r1, rules 1-5):
 * S = the base state; address(S) and address(pauseSuccessorV4(S)) (one
 * compile).
 *   1  base.covenantId must be a canonical 32-byte lowercase hex string, else
 *      there are no candidates: step 8 adopts nothing and forces nothing.
 *   3  L itself or the recorded old outpoint observed there is never ignored,
 *      whatever its covenant id: CHAIN_CONTRADICTION.
 *   2  a candidate is an output there whose covenant id equals base.covenantId
 *      exactly; an output with no covenant id or another one is ignored (no
 *      candidate, no evidence, no status depends on it).
 *   4  C-bound refusals: more than one candidate across both addresses, or the
 *      one candidate Y with a value other than pv+fr or a txid that is the
 *      creation txid or a recorded request's -> CHAIN_CONTRADICTION.
 *   5  no candidate: the pass continues (steps 9-11).
 * The one candidate Y is adopted at depth >= D (CLAIM_PENDING below): live = Y,
 * status by paused, lastTransition ownerPause|ownerUnpause. Adoption settles
 * no losers (L-6).
 */
async function adoptOutOfApp(config, ctx, current, vDaa) {
  const { vaultId, m, base, reqs, chain } = ctx, L = base.outpoint, C = base.covenantId;
  if (typeof C !== "string" || !HEX64.test(C)) return null; // rule 1
  const template = { owner: m.template.owner, vaultId: m.vaultId };
  const flipState = pauseSuccessorV4(base.state, base.state.paused !== 1n);
  const flip = successorAddressAndScript(config, template, stateToJsonV4(flipState), m.contractVersion);
  const observed = [];
  for (const [state, compiled] of [[base.state, current], [flipState, flip]]) {
    for (const u of await chain.read(compiled.address)) observed.push({ u, state, compiled, Y: { transactionId: u.outpoint.transactionId, index: u.outpoint.index } });
  }
  const old = m.lastTransition?.oldOutpoint ?? null;
  if (observed.some(({ Y }) => exactOutpoint(Y, L) || exactOutpoint(Y, old))) { // rule 3
    return contradiction(vaultId, "the recorded outpoint or the recorded old outpoint is observed at the recorded state's addresses");
  }
  const candidates = observed.filter(({ u }) => u.covenantId === C); // rule 2: every other output is ignored
  if (!candidates.length) return null; // rule 5
  if (candidates.length > 1) return contradiction(vaultId, "more than one candidate successor is observed at the recorded state's addresses");
  const { u, state, compiled, Y } = candidates[0];
  const recorded = new Set(reqs.map((r) => r.txId).filter((txId) => typeof txId === "string"));
  if (u.amount !== base.value || Y.transactionId === m.creationTxId || recorded.has(Y.transactionId)) {
    return contradiction(vaultId, "an output with the vault's covenant id at the recorded state's addresses is not an adoptable successor");
  }
  const depth = depthOf(vDaa, u);
  if (depth < SETTLE_DEPTH_DAA) {
    return belowDepth(vaultId, depth, { txId: Y.transactionId, reason: "a successor made outside PolicyVault is observed below the settlement depth; nothing was written" });
  }
  const stateId = computeStateIdV4({ networkId: m.networkId, template: m.template, state, contractVersion: m.contractVersion });
  const action = state.paused === 1n ? "ownerPause" : "ownerUnpause";
  await persistManifestV4(config, { ...manifestToJson(m), status: statusOf(state),
    live: { state: stateToJsonV4(state), stateId, outpoint: Y, outpointValue: String(base.value), scriptSha256: compiled.scriptSha256, covenantId: base.covenantId },
    latestTransitionTxId: Y.transactionId,
    lastTransition: { action, txId: Y.transactionId, oldStateId: base.stateId, newStateId: stateId, oldOutpoint: { transactionId: L.transactionId, index: Number(L.index) }, newOutpoint: Y } });
  await appendAudit(config, { vaultId, action: "reconciled_advanced", actor: "system", via: "adopted", txId: Y.transactionId, result: "CHAIN_VERIFIED", oldStateId: base.stateId, newStateId: stateId });
  return { status: "ADVANCED", vaultId, to: action, txId: Y.transactionId, adopted: true, stateId, settled: [] };
}

/*
 * Step 9 (§2.5(3); CR-M2, CR-M3, CR-L4, L-12): the owner-pasted recover X of L
 * (`outOfAppTransaction`, Safe JSON; absent -> null). It grants no authority:
 * only the chain can make it settle anything.
 *   - the engine parses the document and RECOMPUTES X (the embedded id is
 *     never trusted); the checks follow the covenant's ownerRecover branch
 *     (PolicyVault.v0.4.1.sil ownerRecover): SOME input spends L exactly;
 *     outputs[0] pays P2PK(template.owner) exactly pv+fr; NO output carries
 *     the vault's covenant id C (every other entrypoint continues C, so an
 *     accepted spend of L without a C output terminated the covenant);
 *   - acceptance: one output X:i observed exactly (value, script bytes,
 *     version, covenant binding) at depth >= D; below D -> CLAIM_PENDING,
 *     nothing written;
 *   - the read cap (RC45 R1-09; S-03, C9): in output order, outputs[0]'s
 *     address first, then at most 4 further distinct output addresses are
 *     read; an output at any other address is not read and those addresses
 *     are counted as unchecked (step 0 refuses more than 64 outputs);
 *   - any mismatch settles nothing: {mismatch, unchecked} and the pass
 *     continues with steps 10-11 (UNKNOWN or CHAIN_CONTRADICTION, no write).
 * At D every record written is validated first (an environment error is a
 * 422 with nothing written): the journal-free PENDING records exactly on L
 * with another txid (losers) and the journal-free txid-X records (twins).
 * Order (plan §4 "Recover evidence"): losers STALE first (settleLoser against
 * the input equal to L), the manifest RECOVERED through
 * advanceManifestAndRegistryV4 with case B's synthetic request built from
 * `base` (never the null live of a TERMINATED_UNKNOWN vault), the create-only
 * case-B receipt, one reconciled_recovered {via: "owner-evidence"} row; then
 * identity-valid txid-X records get twinComplete (identity-invalid ones stay
 * untouched, never STALE).
 */
async function recoverEvidence(config, ctx, vDaa) {
  const { vaultId, m, base, reqs, chain, settled, outOfAppTransaction } = ctx, L = base.outpoint, C = base.covenantId;
  if (outOfAppTransaction === undefined) return null;
  const mismatch = (reason, unchecked = 0) => ({ mismatch: reason, unchecked });
  if (typeof C !== "string" || !HEX64.test(C)) return mismatch("the recorded state carries no canonical covenant id");
  let X;
  try {
    X = parseSignedTransactionSafeJson(config, outOfAppTransaction);
  } catch (error) {
    if (error?.code === "TX_IDENTITY_INVALID") return mismatch(`it is not a readable signed transaction (${error.message})`);
    throw error;
  }
  const spent = X.inputs.find((input) => exactOutpoint(input.previousOutpoint, L))?.previousOutpoint ?? null;
  if (!spent) return mismatch("no input spends the recorded outpoint");
  const payout = X.outputs[0];
  if (!payout || payout.scriptVersion !== 0 || payout.scriptPublicKeyHex !== `20${m.template.owner}ac` || payout.value !== base.value) {
    return mismatch("outputs[0] does not pay the vault owner exactly the recorded value");
  }
  if (X.outputs.some((o) => o.covenantId === C)) return mismatch("an output carries the vault's covenant id (the covenant continues)");

  // Acceptance: one output of X observed exactly, at depth >= D, read under the cap (R1-09): outputs[0]'s address
  // (it pays the owner, so it has one) opens the window, then at most 4 further distinct output addresses join it.
  const admitted = new Set(), unread = new Set();
  let hit = null;
  for (const o of X.outputs) {
    let address;
    try { address = frozenScriptAddress(config, { version: o.scriptVersion, scriptHex: o.scriptPublicKeyHex }); } catch { continue; }
    if (!admitted.has(address)) {
      if (admitted.size > OUT_OF_APP_FURTHER_ADDRESSES) { unread.add(address); continue; }
      admitted.add(address);
    }
    const s = { index: o.index, value: o.value, scriptHex: o.scriptPublicKeyHex, version: o.scriptVersion, covenantId: o.covenantId };
    const u = (await chain.tryRead(address))?.find((entry) => observedAs(entry, X.transactionId, s));
    if (!u) continue;
    const depth = depthOf(vDaa, u);
    if (hit === null || depth > hit.depth) hit = { index: o.index, depth };
    if (depth >= SETTLE_DEPTH_DAA) break;
  }
  if (!hit) {
    if (!unread.size) return mismatch("no output of it is observed exactly");
    return mismatch(`no output of it is observed exactly at the ${admitted.size} output addresses read; ${unread.size} further output address(es) beyond the read cap were not read`, unread.size);
  }
  if (hit.depth < SETTLE_DEPTH_DAA) {
    return { result: belowDepth(vaultId, hit.depth, { txId: X.transactionId,
      reason: "the pasted recover of the recorded outpoint is observed below the settlement depth; nothing was written" }) };
  }

  // CONFIRMED: validate every record written before the first write.
  const losers = [], twins = [];
  for (const r of reqs) {
    if (!transitionRecord(r) || r.transitionRecovery) continue;
    if (r.txId === X.transactionId) {
      const v = validated(config, r);
      if (v) twins.push({ r, v });
      continue;
    }
    if (!exactOutpoint(r.predecessorOutpoint, L) || !(await isPending(config, r))) continue;
    const v = validated(config, r);
    if (v) losers.push({ r, v });
  }
  const winner = { txId: X.transactionId, spent };
  for (const loser of losers) await settleLoser(config, loser, winner, hit.depth, settled);
  const synthetic = { predecessorOutpoint: { transactionId: L.transactionId, index: Number(L.index) }, predecessorStateId: base.stateId, sdkAction: "ownerRecover", action: "ownerRecover" };
  await advanceManifestAndRegistryV4(config, m, synthetic, { kind: "recover", txId: X.transactionId, index: hit.index, valueSompi: String(base.value) });
  await getStore(config).createExclusive(Categories.RECEIPT, X.transactionId, { schema: RECEIPT_SCHEMA, txId: X.transactionId, vaultId: m.vaultId, action: "ownerRecover",
    proof: { consumedOutpoint: `${L.transactionId}:${Number(L.index)}`, recoveredValue: String(base.value), reconciled: true }, verifiedAt: new Date().toISOString() });
  await appendAudit(config, { vaultId: m.vaultId, action: "reconciled_recovered", actor: "system", via: "owner-evidence", txId: X.transactionId, result: "CHAIN_VERIFIED", oldStateId: base.stateId });
  for (const t of twins) await twinComplete(config, t, settled);
  return { result: { status: "ADVANCED", vaultId, to: "RECOVERED", txId: X.transactionId, settled } };
}

/*
 * Step 10 (CR2-L6): the recorded old outpoint live again at the address of the
 * frozen input that spent it, or a request ON it with another txid SEEN (step
 * 7's grouping, dedupe and cap; skipped groups are counted as unchecked).
 */
async function ancestorContradiction(config, ctx) {
  const { m, reqs, chain } = ctx, t = m.lastTransition;
  if (!t) return { unchecked: 0 };
  const old = t.oldOutpoint;
  const spenders = reqs.filter((r) => transitionRecord(r) && exactOutpoint(r.predecessorOutpoint, old));
  for (const r of [...spenders.filter((x) => x.txId === t.txId), ...spenders.filter((x) => x.txId !== t.txId)]) {
    let input;
    try { input = normalizeFrozenTxV3(r.build?.frozen).inputs[0]; } catch { continue; }
    if (!exactOutpoint(input.previousOutpoint, old)) continue;
    let address;
    try { address = frozenScriptAddress(config, input.utxo.scriptPublicKey); } catch { continue; }
    const entries = await chain.tryRead(address);
    if (entries?.some((u) => u.outpoint.transactionId === old.transactionId && u.outpoint.index === Number(old.index))) {
      return { contradiction: "the recorded old outpoint is live again" };
    }
    break;
  }
  const { kept, skipped } = await candidateGroups(config, reqs, old, { exceptTxId: t.txId });
  if ((await observeGroups(chain, kept)).size) return { contradiction: "another recorded transaction is observed spending the recorded old outpoint" };
  return { unchecked: skipped };
}

module.exports = { reconcileVaultV4, reconcileVaultV4Unlocked, finishRecordedV4, listSettlementRequests, pastedOutputCount, SETTLE_DEPTH_DAA, OUT_OF_APP_TRANSACTION_MAX_BYTES, OUT_OF_APP_TRANSACTION_MAX_OUTPUTS, DEFAULT_STALE_PENDING_MINIMUM_MS };
