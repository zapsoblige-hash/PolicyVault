"use strict";

/*
 * EXECUTION ATTESTATION EXPORT (server side).
 *
 * Spec: docs/postlaunch/execution-attestation-spec.md
 * Record + verifier: core/attest (portable; the CLI, the browser and the
 * mobile app run the SAME code — this module only ASSEMBLES a record from
 * durable evidence and then hands it to the shared builder, which refuses
 * anything the shared verifier would reject).
 *
 * NO SECOND SOURCE OF FINANCIAL TRUTH. Every field is read from durable
 * records that already exist:
 *
 *   policyvault-wallet-request/v4      (sdk/src/wallet-requests-v4.js)
 *   policyvault-intent-manifest-record/v1 (server/src/intent-records.js,
 *                                      loaded with the MANDATORY G-2
 *                                      read-side re-hash and RE-VERIFIED
 *                                      NOW, never trusting the stored
 *                                      verdict)
 *   policyvault-receipt/v1             (written ONLY after the exact
 *                                      chain effect was proven)
 *   the vault manifest                 (advanced only by proven chain
 *                                      reconciliation)
 *   org assignments                    (metadata plane; zero authority)
 *
 * Nothing is computed here that those records do not already state, with
 * exactly two deterministic RECOMPUTATIONS from committed evidence:
 * the successor output's ADDRESS from the manifest's committed
 * scriptPublicKey (via the sanctioned read-only SDK leaf
 * sdk/src/tx-identity.js), and sha256 digests of collected approval
 * signatures. A fact no durable record carries is emitted as the explicit
 * NOT_AVAILABLE sentinel or null — NEVER fabricated, NEVER backfilled.
 *
 * WHAT THIS MODULE DELIBERATELY WILL NOT DO
 *  - It never dials a Kaspa node. An export must not fail because the node
 *    is down, and a live read here would be a NEW claim rather than a
 *    report of proven evidence. Re-checking chain facts is the READER's
 *    job (tools/attestation-verify.js --chain), which is the whole point
 *    of an independently verifiable record.
 *  - It never emits VERIFIED_OUTCOME. That rung means the ECONOMIC result
 *    was proven, and PolicyVault keeps no durable outcome record for
 *    v0.4/v0.5 spends today (the v0.6 swap proof tool does, outside the
 *    hosted pipeline). Claiming it from a successor receipt would collapse
 *    the ladder — exactly what the ladder exists to prevent.
 *  - It never signs anything. The attestation's detached signature slot
 *    stays null: no server-held key goes anywhere near funds or evidence.
 */

const attest = require("../../core/attest");
const wr4 = require("../../sdk/src/wallet-requests-v4");
const { getStore, Categories } = require("../../sdk/src/store");
const { loadAnyManifest } = require("../../sdk/src/manifest-v2");
const { assignmentFor } = require("../../sdk/src/organization");
const { loadManifestRecord } = require("./intent-records");
const { verifyIntentManifest } = require("../../core/intent");

const NA = attest.NOT_AVAILABLE;
const APPROVER_SENTINEL = "00".repeat(32);

/*
 * "PolicyVault never produced a verified authorization for this
 * transaction" — and ONLY that. These two states name a failure of the
 * authority/quorum check itself, so the attestation's decision is REFUSED.
 *
 * Every OTHER post-build failure is deliberately NOT a refusal of the
 * authorization: PolicyVault DID authorize, and something afterwards went
 * wrong. Reporting a declined wallet signature or a node rejection as
 * "PolicyVault refused" would misattribute the refusal — so those become
 * decision AUTHORIZED with disposition FAILED and the exact state as the
 * failure code (see POST_AUTHORIZATION_FAILURE_STATES).
 */
const REFUSAL_STATES = Object.freeze(new Set([wr4.RequestState.AUTHORIZATION_FAILED, wr4.RequestState.INSUFFICIENT_APPROVALS]));

/*
 * Authorized, then failed before any chain proof. The ladder stops at
 * AUTHORIZED (conservatively: a rejected or invalid signature must never
 * be narrated as "an external signer returned a signature"), except a
 * node-rejected submission, which is reached only from a validly signed
 * request.
 */
const POST_AUTHORIZATION_FAILURE_STATES = Object.freeze(
  new Set([
    wr4.RequestState.WALLET_REJECTED,
    wr4.RequestState.SIGNATURE_INVALID,
    wr4.RequestState.PREFLIGHT_FAILED,
    wr4.RequestState.STALE,
    wr4.RequestState.CLAIM_CONFLICT
  ])
);

/* States that prove an external signer returned a signature PolicyVault
 * accepted. */
const SIGNED_STATES = Object.freeze(
  new Set([
    wr4.RequestState.SIGNED,
    wr4.RequestState.FINALIZED,
    wr4.RequestState.PREFLIGHT_VERIFIED,
    wr4.RequestState.SUBMITTING,
    wr4.RequestState.SUBMITTED,
    wr4.RequestState.CHAIN_VERIFIED,
    wr4.RequestState.RECONCILIATION_REQUIRED,
    wr4.RequestState.TERMINATED_UNKNOWN
  ])
);

function attestError(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

function parseOutpointString(text) {
  if (typeof text !== "string") return null;
  const m = /^([0-9a-f]{64}):(\d{1,5})$/.exec(text);
  return m ? { transactionId: m[1], index: Number(m[2]) } : null;
}

/*
 * The successor output's address, recomputed from the scriptPublicKey the
 * intent manifest already committed to. Fails CLOSED: an attestation that
 * cannot name the address a reader must query would be unverifiable, and
 * silently downgrading the ladder instead would be worse than an error.
 */
function successorAddress(config, manifestRecord, index) {
  const output = manifestRecord?.manifest?.transaction?.outputs?.[index];
  if (!output || !output.scriptPublicKey || typeof output.scriptPublicKey.scriptHex !== "string") {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `the recorded manifest does not describe output ${index} — refusing to attest to an output it cannot name`);
  }
  if (output.scriptPublicKey.version !== 0) {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `output ${index} uses script version ${output.scriptPublicKey.version}; only version 0 addresses are derivable — failing closed`);
  }
  let address;
  try {
    address = require("../../sdk/src/tx-identity").addressForScriptPublicKey(config, output.scriptPublicKey.scriptHex);
  } catch (e) {
    throw attestError(500, "ATTESTATION_ADDRESS_DERIVATION_FAILED", `could not derive the observed output's address: ${e.message}`);
  }
  if (!address) {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `output ${index} is not a standard address script — no address to re-check`);
  }
  return { address, output };
}

/*
 * v0.7 ORGANIZATIONAL ROOT (Wave 2, Track G): a SIBLING assembly module,
 * `server/src/attestations-v7.js`, maps `ORG_ROOT_REQUEST` records
 * (docs/postlaunch/v0.7-app-surface-contract.md §1) into
 * policyvault-0.7-root / policyvault-0.7-payment attestations. It is
 * required lazily (this module must keep loading even before
 * `server/src/org-roots.js` — a parallel Wave 2 track — exists) and
 * dispatched here by `schemaVersion` so a caller that loads EITHER an
 * ORG_ROOT_REQUEST or a wr4 REQUEST by id and hands it to this ONE
 * function gets the right mapping without knowing which generation it is.
 */
function attestationsV7() {
  return require("./attestations-v7");
}

/*
 * Build ONE policyvault-execution-attestation/1 record for a durable v0.4
 * wallet request. Returns { attestation, sources } or throws.
 */
async function buildAttestationForRequest(config, request, { vault = undefined } = {}) {
  if (request && request.schemaVersion === attestationsV7().ORG_ROOT_REQUEST_SCHEMA_V1) {
    return attestationsV7().buildAttestationForOrgRootRequest(config, request);
  }
  if (!request || request.schema !== wr4.REQUEST_SCHEMA_V4) {
    throw attestError(404, "ATTESTATION_SUBJECT_NOT_FOUND", "no attestable request");
  }
  const sources = ["policyvault-wallet-request/v4"];
  const build = request.build ?? null;
  const store = getStore(config);

  /* --- intent-manifest evidence: G-2 re-hash on read, RE-VERIFIED NOW --- */
  let manifestRecord = null;
  let liveVerdict = null;
  if (typeof request.manifestHash === "string") {
    manifestRecord = await loadManifestRecord(config, request.manifestHash); // throws on integrity divergence
    if (manifestRecord) {
      sources.push("policyvault-intent-manifest-record/v1");
      liveVerdict = verifyIntentManifest({ manifest: manifestRecord.manifest });
    }
  }

  /* --- chain-proof evidence --- */
  const receipt = request.txId ? await store.read(Categories.RECEIPT, request.txId) : null;
  if (receipt) sources.push("policyvault-receipt/v1");

  /* --- organization (metadata plane; zero covenant authority) --- */
  const assignment = await assignmentFor(config, request.vaultId);
  if (assignment) sources.push("policyvault-org-assignments/v1");
  const loadedVault = vault === undefined ? await loadAnyManifest(config, request.vaultId).catch(() => null) : vault;
  if (loadedVault) sources.push(`policyvault-vault-manifest/${loadedVault.version}`);

  /* ---------------- authorization decision ---------------- */
  let decision = "AUTHORIZED";
  let refusalCode = null;
  if (request.intentRecording === "FAILED") {
    decision = "REFUSED";
    refusalCode = "INTENT_DERIVATION_FAILED";
  } else if (manifestRecord && liveVerdict && liveVerdict.ok !== true) {
    decision = "REFUSED";
    refusalCode = "INTENT_VERIFICATION_FAILED";
  } else if (REFUSAL_STATES.has(request.state)) {
    decision = "REFUSED";
    refusalCode = request.state;
  }

  /* ---------------- the ladder, from durable evidence only ---------------- */
  const reached = [];
  let disposition = "IN_PROGRESS";
  let failureCode = null;
  let txId = null;
  const chainVerified = receipt !== null && request.state === wr4.RequestState.CHAIN_VERIFIED;

  if (decision === "AUTHORIZED") {
    reached.push({
      state: "AUTHORIZED",
      source: manifestRecord ? "intent-manifest-record-v1" : "wallet-request-v4",
      note: manifestRecord ? `intent manifest re-verified ${liveVerdict.verdict} at export time` : "recorded before intent-manifest recording existed"
    });
    if (POST_AUTHORIZATION_FAILURE_STATES.has(request.state)) {
      disposition = "FAILED";
      failureCode = request.state;
    } else if (request.state === wr4.RequestState.SUBMISSION_REJECTED) {
      reached.push({ state: "SIGNED", source: "wallet-request-v4", note: "the request was finalized with an accepted signature before the node refused it" });
      disposition = "FAILED";
      failureCode = "SUBMISSION_REJECTED";
    } else {
      if (SIGNED_STATES.has(request.state)) {
        reached.push({ state: "SIGNED", source: "wallet-request-v4", note: `request state ${request.state}` });
      }
      const broadcast = receipt !== null || request.state === wr4.RequestState.SUBMITTED || request.state === wr4.RequestState.CHAIN_VERIFIED;
      if (reached.length === 2 && broadcast) {
        txId = request.txId ?? null;
        reached.push({ state: "BROADCAST", source: "wallet-request-v4", note: "the node returned the frozen transaction id" });
        if (chainVerified) {
          reached.push({ state: "CHAIN_SEEN", source: "implied-by-chain-verified", note: "the exact expected effect was read back from the node" });
          reached.push({ state: "CHAIN_VERIFIED", source: "receipt-v1", note: "receipt written only after the exact expected effect was proven on chain" });
        }
      }
      if (chainVerified) disposition = "SETTLED";
      else if (request.state === wr4.RequestState.RECONCILIATION_REQUIRED || request.state === wr4.RequestState.TERMINATED_UNKNOWN) {
        disposition = "UNKNOWN";
        failureCode = request.state;
      }
    }
  } else {
    disposition = "REFUSED";
  }
  /* VERIFIED_OUTCOME is never synthesized here — see the header. */

  /* ---------------- observed chain outputs (only what was PROVEN) ---------------- */
  let outputs = [];
  let successorOutpoint = null;
  let successorCovenantId = null;
  if (chainVerified) {
    const proof = receipt.proof ?? {};
    const outpoint = parseOutpointString(proof.successorOutpoint) ?? parseOutpointString(proof.outpoint);
    if (outpoint === null) {
      /* A terminal recover proves an owner PAYOUT, not a successor; the
       * v4 receipt records it as `successorOutpoint: null`. Without a
       * proven outpoint there is nothing to name for re-checking, so the
       * ladder cannot honestly reach CHAIN_VERIFIED in this record. */
      reached.length = Math.min(reached.length, 3);
      disposition = "IN_PROGRESS";
      failureCode = null;
    } else {
      successorOutpoint = outpoint;
      const { address, output } = successorAddress(config, manifestRecord, outpoint.index);
      successorCovenantId = output.covenant ? output.covenant.covenantId : null;
      outputs = [
        {
          index: outpoint.index,
          address,
          valueSompi: String(proof.value ?? output.value),
          covenantId: successorCovenantId,
          blockDaaScore: null // PolicyVault does not persist the accepting DAA score today
        }
      ];
    }
  }

  /* ---------------- amounts, asset, destination ---------------- */
  /*
   * GENESIS and TRANSITION builds carry DIFFERENT accounting shapes (a
   * genesis has no predecessor, no payment and no covenant sighash), so
   * each is mapped explicitly. A shape this code does not recognise
   * yields NOT_AVAILABLE rather than a coerced value — "undefined"
   * stringified into a financial field is exactly the class of defect
   * this schema exists to make impossible.
   */
  const isGenesis = request.kind === "genesis";
  const payment = manifestRecord?.manifest?.payment ?? null;
  const accounting = build?.accounting ?? null;
  const terminal = build && Object.prototype.hasOwnProperty.call(build, "successorState") ? build.successorState === null : false;
  let amount = NA;
  if (payment) amount = String(payment.amountSompi);
  else if (isGenesis && accounting?.vaultValue !== undefined) amount = String(accounting.vaultValue);
  else if (accounting && terminal && accounting.terminalPayout !== undefined) amount = String(accounting.terminalPayout);
  else if (accounting && accounting.payAmount !== undefined) amount = String(accounting.payAmount);

  let destination = { kind: NA, identity: null, scriptHex: null };
  if (payment) {
    destination = { kind: "RECIPIENT_XONLY", identity: payment.recipientXOnly, scriptHex: null };
  } else if (isGenesis) {
    destination = { kind: "COVENANT_SUCCESSOR", identity: null, scriptHex: null };
  } else if (terminal && loadedVault?.manifest?.template?.owner) {
    destination = { kind: "OWNER_PAYOUT", identity: loadedVault.manifest.template.owner, scriptHex: null };
  } else if (accounting) {
    destination = { kind: "NONE", identity: null, scriptHex: null };
  }

  /* ---------------- approvals (counts + digests; never signatures) ---------------- */
  const pkg = request.approvalPackage ?? null;
  /* transition builds carry stateJson (the PREDECESSOR state); genesis
   * builds carry initialState (the state being created). */
  const stateJson = build?.stateJson ?? build?.initialState ?? request.initialState ?? null;
  const slots = (stateJson?.approverSlots ?? pkg?.approverSlots ?? []).filter((s) => typeof s === "string" && s !== APPROVER_SENTINEL);
  const collectedDigests = [];
  if (pkg && Array.isArray(pkg.approvals)) {
    pkg.approvals.forEach((signatureHex, slot) => {
      if (typeof signatureHex !== "string" || signatureHex.length === 0) return;
      const approverXOnly = pkg.approverSlots?.[slot];
      if (typeof approverXOnly !== "string" || approverXOnly === APPROVER_SENTINEL) return;
      collectedDigests.push({ slot: String(slot), approverXOnly, signatureDigest: attest.approvalSignatureDigest(signatureHex) });
    });
  }
  const aboveThreshold = request.aboveThreshold === true;
  const required = aboveThreshold ? String(pkg?.approvalM ?? stateJson?.approvalM ?? "0") : "0";

  /* ---------------- assemble ---------------- */
  const body = {
    attestationVersion: attest.ATTESTATION_VERSION_1,
    producedAt: new Date().toISOString(),
    producer: {
      software: "policyvault",
      buildId: config.buildId ?? NA,
      component: "server-attestation-export",
      sources: [...new Set(sources)]
    },
    subject: {
      requestId: request.requestId,
      vaultId: request.vaultId,
      organizationId: assignment?.orgId ?? null,
      networkId: config.networkId,
      contractVersion: request.contractVersion,
      policyNonce: stateJson?.policyNonce ?? NA,
      stateBefore: isGenesis ? null : (request.predecessorStateId ?? null),
      stateAfter: isGenesis ? (build?.stateId ?? null) : (request.successorStateId ?? null)
    },
    action: {
      type: request.sdkAction ?? request.action,
      highLevel: request.highLevel ?? null,
      role: request.signerRole ?? NA,
      aboveThreshold
    },
    authorization: {
      decision,
      refusalCode,
      intentManifestHash: manifestRecord ? manifestRecord.manifestHash : NA,
      intentManifestVerdict: liveVerdict ? liveVerdict.verdict : NA,
      signerVisibleDigest: build?.covenantSighash ?? NA, // a genesis spends ordinary fuel: no covenant sighash exists
      /* the genesis request row records the signer ADDRESS; the recorded
       * manifest commits to the same signer's x-only key, so the identity
       * comes from committed evidence rather than a re-derivation */
      signerXOnly: request.signerXOnly ?? manifestRecord?.manifest?.actor?.signerXOnly ?? NA
    },
    approvals: {
      required,
      collected: String(collectedDigests.length),
      approverSlots: slots,
      packageCommitment: pkg?.commitment ?? null,
      approvalDigests: collectedDigests
    },
    /* v0.4/v0.4.1 requests are KAS-denominated; token and swap generations
     * get their own additive mapping when their durable records land. */
    asset: { kind: "KAS", descriptorHash: null, familyId: null, unit: "sompi" },
    destination,
    amounts: {
      amount,
      networkFeeSompi: receipt?.proof?.actualFeeSompi ?? accounting?.fee ?? build?.requiredFeeSompi ?? NA,
      protocolFeeSompi: null
    },
    outcome: {
      state: reached.length === 0 ? "REFUSED" : reached[reached.length - 1].state,
      disposition,
      failureCode,
      reached,
      txId: decision === "REFUSED" ? null : txId,
      networkId: config.networkId,
      chain: {
        acceptingBlockDaaScore: null, // not persisted today (see the spec's residuals)
        observedVirtualDaaScore: null,
        depthDaa: null,
        minDepthDaa: null,
        predecessorOutpoint: build?.predecessorOutpoint ?? null,
        successorOutpoint,
        successorStateId: chainVerified ? (isGenesis ? (build?.stateId ?? null) : (request.successorStateId ?? null)) : null,
        covenantId: successorCovenantId,
        scriptSha256: chainVerified ? (build?.successorScriptSha256 ?? build?.scriptSha256 ?? null) : null,
        outputs
      }
    }
  };

  let attestation;
  try {
    attestation = attest.buildExecutionAttestation(body);
  } catch (e) {
    /* The shared builder runs the shared verifier: reaching here means the
     * durable evidence itself is internally inconsistent. Report it as an
     * integrity alarm rather than shipping a record that fails
     * verification in the reader's hands. */
    throw attestError(409, e.code === "ATTESTATION_INVALID" ? "ATTESTATION_EVIDENCE_INCONSISTENT" : (e.code ?? "ATTESTATION_BUILD_FAILED"), e.message);
  }
  return { attestation, sources: body.producer.sources };
}

/* Every attestable request for one vault, newest first, bounded. */
async function buildAttestationsForVault(config, vaultId, { limit = 50, vault = undefined } = {}) {
  const requests = await wr4.listVaultRequests(config, vaultId);
  const out = [];
  for (const request of requests.slice(0, limit)) {
    out.push((await buildAttestationForRequest(config, request, { vault })).attestation);
  }
  return out;
}

module.exports = {
  REFUSAL_STATES,
  POST_AUTHORIZATION_FAILURE_STATES,
  SIGNED_STATES,
  buildAttestationForRequest,
  buildAttestationsForVault,

  /*
   * v0.7 ORGANIZATIONAL ROOT (Wave 2, Track G) — re-exported from the
   * sibling assembly module `server/src/attestations-v7.js` so a caller
   * never needs to know it exists as a separate file. `buildAttestationForRequest`
   * above already dispatches to `buildAttestationForOrgRootRequest` for any
   * record carrying `schemaVersion: "policyvault-org-root-request/1"`; the
   * names below are for callers that want the v0.7-specific functions
   * directly (e.g. `buildAttestationsForOrgRootRequestVaultOps`, which has
   * no v4 analogue: one root transaction can carry several rooted-vault
   * attestations).
   */
  get ORG_ROOT_REQUEST_SCHEMA_V1() {
    return attestationsV7().ORG_ROOT_REQUEST_SCHEMA_V1;
  },
  get ORG_ROOT_REQUEST_CATEGORY() {
    return attestationsV7().ORG_ROOT_REQUEST_CATEGORY;
  },
  get loadOrgRootRequestForAttestation() {
    return attestationsV7().loadOrgRootRequestForAttestation;
  },
  get buildAttestationForOrgRootRequest() {
    return attestationsV7().buildAttestationForOrgRootRequest;
  },
  get buildAttestationsForOrgRootRequestVaultOps() {
    return attestationsV7().buildAttestationsForOrgRootRequestVaultOps;
  },
  get buildAttestationForRootedVaultRequest() {
    return attestationsV7().buildAttestationForRootedVaultRequest;
  }
};
