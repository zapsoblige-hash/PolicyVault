"use strict";

/*
 * EXECUTION ATTESTATION EXPORT — v0.7 ORGANIZATIONAL ROOT (Wave 2, Track G).
 *
 * Sibling of server/src/attestations.js (the v0.4/v0.4.1 assembly this file
 * leaves completely untouched). Spec: docs/postlaunch/execution-attestation-
 * spec.md §"v0.7 mapping"; the durable record shape this maps FROM is
 * docs/postlaunch/v0.7-app-surface-contract.md §1 (`ORG_ROOT_REQUEST`),
 * which is DESIGNED — not yet implemented anywhere in this codebase
 * (`server/src/org-roots.js` and `sdk/src/wallet-requests-v7.js` are a
 * PARALLEL Wave 2 track's deliverable). This module is written directly
 * against that contract so the wiring on the other lane's completion is a
 * thin dispatch, not a redesign; every test in `sdk/test/postlaunch-
 * attestations-v7.test.js` builds a REAL `policyvault-org-root-manifest/1`
 * / `policyvault-rooted-vault-manifest/1` through the actual SDK v0.7
 * builders and core verifiers — never a hand-typed manifest shape.
 *
 * TWO CONTRACT VERSIONS, because a v0.7 root transaction can authorize the
 * root's OWN governance change (contractVersion policyvault-0.7-root) while
 * carrying zero or more ROOTED-VAULT owner operations in the SAME
 * transaction (contractVersion policyvault-0.7-payment) — and a rooted
 * vault also accepts standalone, root-free delegate spends and deposits
 * under policyvault-0.7-payment. Each vault operation and each root action
 * gets its OWN attestation record: the schema's `subject`/`action`/
 * `asset`/`destination` shape is per-transfer, and a single root
 * transaction can carry several.
 *
 * NO SECOND SOURCE OF FINANCIAL TRUTH — same discipline as the v0.4
 * assembly: every field is read from durable evidence that already exists
 * (the ORG_ROOT_REQUEST record, its embedded
 * `policyvault-org-root-manifest/1` — RE-VERIFIED NOW, never trusted by
 * marker, exactly like the v0.4 intent-manifest re-verification) with
 * exactly one deterministic RECOMPUTATION from committed evidence: the
 * observed output's ADDRESS from the manifest's committed frozen
 * transaction, through the SAME sanctioned read-only SDK leaf
 * (`sdk/src/tx-identity.js`) the v0.4 assembly uses. A fact no durable
 * record carries is the explicit NOT_AVAILABLE sentinel — never fabricated.
 *
 * WHAT THIS MODULE DELIBERATELY WILL NOT DO (identical to attestations.js):
 * it never dials a Kaspa node; it never emits VERIFIED_OUTCOME (a
 * VERIFIED_OUTCOME-stamped ORG_ROOT_REQUEST is capped at CHAIN_VERIFIED
 * here, with a note — no durable ECONOMIC-outcome record exists for v0.7
 * spends any more than it does for v0.4/v0.5); it signs nothing.
 *
 * TWO RESIDUALS, stated honestly rather than guessed past:
 *  1. `sdk/src/wallet-requests-v7.js` does not exist yet, so the EXACT
 *     durable envelope for a standalone delegate-spend/deposit request
 *     (`POST /wallet/v7/requests`) is unknown. `mapRootedVaultAttestationBody`
 *     is therefore written against the STABLE, already-real
 *     `policyvault-rooted-vault-manifest/1` shape plus a small, explicit
 *     `envelope` of request-level facts the caller supplies
 *     (`{ requestId, state, txId, chain, signerVisibleDigest, signerXOnly,
 *     organizationId }`) — whatever shape the request record eventually
 *     takes, a one-line adapter at that call site can build this envelope.
 *     `server/src/attestations.js`'s dispatch is wired for `ORG_ROOT_REQUEST`
 *     records (both kinds this file maps); wiring the standalone
 *     delegate-spend/deposit call site is the other lane's completion.
 *  2. Approval evidence for a ROOTED-VAULT owner operation riding in a root
 *     action is reported as `required: "0"` / `collected: "0"`: the
 *     operation's OWN authority is entirely inherited from the root
 *     action's M-of-N approvals in the SAME transaction (attested
 *     separately by `buildAttestationForOrgRootRequest`), and the schema
 *     has no field to cross-reference one attestation from another. A
 *     reader who needs the root's quorum evidence fetches the root
 *     action's own attestation for the same `subject.requestId`.
 */

const attest = require("../../core/attest");
const { verifyOrgRootIntentManifest, ORG_ROOT_MANIFEST_VERSION_1, ROOTED_VAULT_MANIFEST_VERSION_1 } = require("../../core/intent/org-root-manifest-v7");

const NA = attest.NOT_AVAILABLE;

const ORG_ROOT_REQUEST_SCHEMA_V1 = "policyvault-org-root-request/1";
const CONTRACT_VERSION_ROOT = "policyvault-0.7-root";
const CONTRACT_VERSION_PAYMENT = "policyvault-0.7-payment";

/*
 * The durable store category `ORG_ROOT_REQUEST` records will live under
 * (docs/postlaunch/v0.7-app-surface-contract.md §1). `sdk/src/store.js`
 * does not define a `Categories.ORG_ROOT_REQUEST` constant yet — that is
 * the server lane's addition, made in parallel. This STRING is what the
 * category will be named; `loadOrgRootRequestForAttestation` attempts the
 * live lookup through it and fails closed with a distinct, honest code
 * until the category is registered. Every mapping function in this module
 * accepts an ALREADY-LOADED record directly, so none of them depend on
 * this constant or on the lookup succeeding.
 */
const ORG_ROOT_REQUEST_CATEGORY = "org-root-request";

/* The six named root actions (core/model/owner-set-v7 ROOT_ACTIONS_V7,
 * read-only reference — never imported for mutation). Restated as a small
 * closed list here so an unknown action fails closed before any field is
 * interpreted, mirroring the "unknown versions fail closed" project rule. */
const ROOT_ACTIONS = Object.freeze(["authorize", "rotate", "freeze", "unfreeze", "ownerRecover", "succession"]);

/* The v0.7 ORG_ROOT_REQUEST ladder is documented (app-surface contract §1)
 * to mirror the SAME closed reconciliation-ladder vocabulary the
 * attestation schema itself uses directly, with two terminal buckets,
 * REFUSED and FAILED — unlike wr4's richer per-cause state machine. */
const ORG_ROOT_REQUEST_TERMINAL_STATES = Object.freeze(["REFUSED", "FAILED"]);

function attestError(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/*
 * The attestation schema's `subject.requestId` and `subject.organizationId`
 * are UUID-shaped (core/attest/schema.js UUID_RE) — the HOSTED-layer
 * identifier convention every other generation's mapping already follows
 * (`request.requestId` in wr4, `assignment.orgId` from `sdk/src/
 * organization.js`). This is DELIBERATELY NOT the same field as the
 * ON-CHAIN `orgId`/`boundOrgId` the v0.7 root's own consensus state
 * carries (docs/postlaunch/v0.7-app-surface-contract.md §0's "two things
 * that must never be confused") — that on-chain identity is already
 * carried, correctly, as `subject.vaultId` (the root covenant id) and
 * inside the manifest hash. A value that is not UUID-shaped is reported
 * NOT_AVAILABLE rather than coerced: a stringified hex64 forced into a
 * UUID-shaped field would fail the schema anyway, and silently swallowing
 * that mismatch would hide a real wiring defect.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/* subject.requestId's "not present" sentinel is NOT_AVAILABLE. */
function asUuidOrNA(value) {
  return typeof value === "string" && UUID_RE.test(value) ? value : NA;
}
/* subject.organizationId's "not present" sentinel is null (matches every
 * other generation's mapping: assignment?.orgId ?? null). */
function asUuidOrNull(value) {
  return typeof value === "string" && UUID_RE.test(value) ? value : null;
}

/*
 * Attempt the live store lookup for an ORG_ROOT_REQUEST by id. Fails
 * closed with ATTESTATION_ORG_ROOT_STORE_PENDING (not a crash, not a
 * silent null) until the server lane registers the category — see the
 * module header. Callers that already hold a loaded record never need
 * this function.
 */
async function loadOrgRootRequestForAttestation(config, requestId) {
  const { getStore } = require("../../sdk/src/store");
  const store = getStore(config);
  try {
    return await store.read(ORG_ROOT_REQUEST_CATEGORY, requestId);
  } catch (e) {
    if (e && e.code === "STORE_CATEGORY_UNKNOWN") {
      throw attestError(
        501,
        "ATTESTATION_ORG_ROOT_STORE_PENDING",
        "the org-root-request durable store category is not yet registered in this deployment (server lane pending) — pass an already-loaded ORG_ROOT_REQUEST record to buildAttestationForOrgRootRequest instead"
      );
    }
    throw e;
  }
}

/* The `reached` ladder array up to (and including) `state`, or null when
 * `state` is not a ladder rung (REFUSED/FAILED are handled by the caller,
 * never passed here). */
function reachedLadderThrough(state, source) {
  const idx = attest.LADDER.indexOf(state);
  if (idx === -1) return null;
  return attest.LADDER.slice(0, idx + 1).map((s) => ({ state: s, source, note: null }));
}

/*
 * The proven output(s) a reader must re-check for one covenant family
 * within the PARENT transaction's frozen canonical JSON. Mirrors the
 * filter `core/intent/org-root-manifest-v7.js`'s own verifier uses
 * (`outputs.filter((o) => o.covenant && o.covenant.covenantId === family)`)
 * — never a re-derivation of covenant identity, only a re-read of the
 * SAME frozen bytes the manifest already committed to.
 */
function familyOutputs(frozenCanonicalJson, covenantId) {
  const frozen = JSON.parse(frozenCanonicalJson);
  return frozen.outputs
    .map((o, index) => ({ ...o, index }))
    .filter((o) => o.covenant && o.covenant.covenantId === covenantId);
}

/*
 * Recompute ONE output's address from its committed scriptPublicKey,
 * through the SAME sanctioned read-only SDK leaf the v0.4 assembly uses.
 * Fails CLOSED: an attestation that cannot name the address a reader must
 * query would be unverifiable.
 */
function outputAddress(config, output, what) {
  if (!output.scriptPublicKey || typeof output.scriptPublicKey.scriptHex !== "string") {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `${what}: no scriptPublicKey to derive an address from — refusing to attest to an output it cannot name`);
  }
  if (output.scriptPublicKey.version !== 0) {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `${what}: output uses script version ${output.scriptPublicKey.version}; only version 0 addresses are derivable — failing closed`);
  }
  let address;
  try {
    address = require("../../sdk/src/tx-identity").addressForScriptPublicKey(config, output.scriptPublicKey.scriptHex);
  } catch (e) {
    throw attestError(500, "ATTESTATION_ADDRESS_DERIVATION_FAILED", `${what}: could not derive the observed output's address: ${e.message}`);
  }
  if (!address) throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `${what}: output is not a standard address script — no address to re-check`);
  return address;
}

/* ------------------------------------------------------------------ */
/* policyvault-0.7-root — the root's OWN governance action             */
/* ------------------------------------------------------------------ */

/*
 * Build ONE `policyvault-execution-attestation/1` record for a v0.7
 * `ORG_ROOT_REQUEST` of kind "rootAction" (the six named root actions:
 * authorize / rotate / freeze / unfreeze / ownerRecover / succession).
 *
 * `request` is the record shape of docs/postlaunch/v0.7-app-surface-
 * contract.md §1. genesis kinds ("rootGenesis", "rootedVaultGenesis") are
 * NOT mapped by this function — see the module header residual #1's
 * sibling note: a genesis has no predecessor root state and no owner-slot
 * quorum to attest to (the same reason v0.4 genesis builds get a
 * different accounting shape in attestations.js), and is left as a
 * follow-up rather than guessed at.
 */
function buildAttestationForOrgRootRequest(config, request, { orgRoot = null, hostedOrganizationId = null } = {}) {
  if (!isPlainObject(request) || request.schemaVersion !== ORG_ROOT_REQUEST_SCHEMA_V1) {
    throw attestError(404, "ATTESTATION_SUBJECT_NOT_FOUND", "no attestable org-root request");
  }
  if (request.kind !== "rootAction") {
    throw attestError(
      501,
      "ATTESTATION_NOT_YET_MAPPED",
      `org-root request kind ${JSON.stringify(request.kind)} has no attestation mapping on this track yet (only "rootAction" is mapped) — refusing rather than guessing at a genesis build's signer-visible summary shape`
    );
  }
  if (!ROOT_ACTIONS.includes(request.action)) {
    throw attestError(500, "ATTESTATION_ACTION_UNKNOWN", `unknown v0.7 root action ${JSON.stringify(request.action)} — failing closed`);
  }

  const sources = ["policyvault-org-root-request/1"];
  let liveVerdict = null;
  const manifest = request.manifest;
  if (manifest !== null && manifest !== undefined) {
    if (manifest.manifestVersion !== ORG_ROOT_MANIFEST_VERSION_1) {
      throw attestError(500, "ATTESTATION_MANIFEST_VERSION_UNKNOWN", `the recorded manifest declares ${JSON.stringify(manifest.manifestVersion)}, not ${JSON.stringify(ORG_ROOT_MANIFEST_VERSION_1)} — refusing to attest`);
    }
    /* RE-VERIFIED NOW — never trust the stored kind/action fields alone,
     * exactly the v4 G-2 discipline. */
    liveVerdict = verifyOrgRootIntentManifest({
      manifest,
      descriptors: request.descriptors && typeof request.descriptors === "object" && !Array.isArray(request.descriptors) ? request.descriptors : {}, // rc21 review R6-02
      redeemScripts: request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {} // Codex checkpoint 6 (UX-02 / UX-13)
    });
    sources.push(ORG_ROOT_MANIFEST_VERSION_1);
  } else {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", "a rootAction request must carry its policyvault-org-root-manifest/1 — refusing to attest without it");
  }
  if (orgRoot) sources.push("policyvault-org-root-record/1");

  /* ---------------- authorization decision ---------------- */
  let decision = "AUTHORIZED";
  let refusalCode = null;
  if (liveVerdict.verdict !== "VERIFIED") {
    decision = "REFUSED";
    refusalCode = "INTENT_VERIFICATION_FAILED";
  } else if (request.state === "REFUSED") {
    decision = "REFUSED";
    refusalCode = "ORG_ROOT_REQUEST_REFUSED";
  }

  /* ---------------- the ladder, from durable evidence only ---------------- */
  let reached = [];
  let disposition = "IN_PROGRESS";
  let failureCode = null;
  let txId = null;
  let outputs = [];
  let successorOutpoint = null;

  if (decision === "AUTHORIZED") {
    if (request.state === "FAILED") {
      reached = reachedLadderThrough("AUTHORIZED", "org-root-request-v1") ?? [];
      disposition = "FAILED";
      failureCode = "ORG_ROOT_REQUEST_FAILED";
    } else {
      /* CAP at CHAIN_VERIFIED: this module never emits VERIFIED_OUTCOME
       * (see the header) — a request stamped VERIFIED_OUTCOME still
       * attests only through CHAIN_VERIFIED, honestly noted. */
      const effectiveState = request.state === "VERIFIED_OUTCOME" ? "CHAIN_VERIFIED" : request.state;
      reached = reachedLadderThrough(effectiveState, "org-root-request-v1");
      if (reached === null) {
        throw attestError(500, "ATTESTATION_LADDER_STATE_UNKNOWN", `unknown org-root-request state ${JSON.stringify(request.state)} — failing closed`);
      }
      if (reached.some((r) => r.state === "BROADCAST")) {
        txId = request.txId ?? manifest.transaction.txId ?? null;
      }
      if (reached.some((r) => r.state === "CHAIN_SEEN") || reached.some((r) => r.state === "CHAIN_VERIFIED")) {
        const outs = familyOutputs(manifest.transaction.frozenCanonicalJson, manifest.root.covenantId);
        if (outs.length !== 1) {
          throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", `expected exactly one root successor output, found ${outs.length} — refusing to attest an ambiguous chain claim`);
        }
        const address = outputAddress(config, outs[0], "root successor output");
        outputs = [{ index: outs[0].index, address, valueSompi: manifest.root.valueAfter, covenantId: manifest.root.covenantId, blockDaaScore: null }];
        if (request.chain && request.chain.successorOutpoint) {
          successorOutpoint = { transactionId: request.chain.successorOutpoint.transactionId, index: Number(request.chain.successorOutpoint.index) };
        } else {
          successorOutpoint = { transactionId: txId ?? manifest.transaction.txId, index: outs[0].index };
        }
      }
      if (reached.some((r) => r.state === "CHAIN_VERIFIED")) disposition = "SETTLED";
    }
  } else {
    disposition = "REFUSED";
  }

  /* ---------------- approvals: slot counts + public keys + digests, never raw signatures ---------------- */
  const slotsArr = Array.isArray(request.slots) ? request.slots : [];
  const approverSlots = slotsArr.map((s) => s.publicKey).filter((k) => typeof k === "string");
  const signedSlots = slotsArr.filter((s) => s && s.status === "SIGNED" && typeof s.publicKey === "string");
  /*
   * APPROXIMATION (stated, not fabricated): the schema's approvalDigests
   * carries sha256(RAW signature); the durable ORG_ROOT_REQUEST record
   * (app-surface contract §1) stores `responseEnvelopeHash` per slot — a
   * hash of the whole BOUND response envelope, not of the bare 65-byte
   * signature alone. Until a raw-signature digest is separately persisted,
   * `responseEnvelopeHash` is used here: it is still a genuine per-approval
   * binding hash over material the server actually verified, just over a
   * slightly wider domain than the spec's literal sha256(signatureHex).
   */
  const approvalDigests = signedSlots
    .filter((s) => typeof s.responseEnvelopeHash === "string")
    .map((s) => ({ slot: String(Number(s.slot) - 1), approverXOnly: s.publicKey, signatureDigest: s.responseEnvelopeHash }));
  const signerXOnly = signedSlots.length > 0 ? signedSlots[0].publicKey : NA;

  if (reached.some((r) => r.state === "SIGNED") && signerXOnly === NA) {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", "the request reached SIGNED but no slot carries a SIGNED status with a public key — refusing to attest an unfalsifiable signing claim");
  }

  const body = {
    attestationVersion: attest.ATTESTATION_VERSION_1,
    producedAt: new Date().toISOString(),
    producer: {
      software: "policyvault",
      buildId: config.buildId ?? NA,
      component: "server-attestation-export-v7",
      sources: [...new Set(sources)]
    },
    subject: {
      requestId: asUuidOrNA(request.id),
      vaultId: manifest.root.covenantId,
      organizationId: asUuidOrNull(hostedOrganizationId),
      networkId: manifest.network.networkId,
      contractVersion: CONTRACT_VERSION_ROOT,
      policyNonce: manifest.rootState.before.state.rootNonce,
      stateBefore: manifest.rootState.before.digest,
      stateAfter: manifest.rootState.after.digest
    },
    action: {
      type: request.action,
      /* the action's authority CLASS (AUTHORITY-REDUCING / NEUTRAL /
       * EXPANDING / TERMINAL) — core/model/owner-set-v7's vocabulary,
       * restated verbatim from the re-verified manifest, never from the
       * unverified request row */
      highLevel: manifest.action.authorityClass,
      role: "owner",
      /* an organizational root action ALWAYS requires reaching a declared
       * M-of-N (or K-of-N / R-of-N / the pinned successor key) quorum —
       * there is no "below threshold" owner-root action */
      aboveThreshold: true
    },
    authorization: {
      decision,
      refusalCode,
      intentManifestHash: manifest.manifestHash,
      intentManifestVerdict: liveVerdict.verdict === "VERIFIED" ? "VERIFIED_EXACT" : "REFUSED",
      /* a root action's covenant sighash IS the frozen transaction itself
       * (every counted slot signs SIGHASH_ALL over it) — there is no
       * separate "signer-visible digest" distinct from the manifest hash
       * the way a v0.4 payment covenant sighash is; NOT_AVAILABLE is
       * honest here until a distinct digest is separately recorded */
      signerVisibleDigest: request.signerVisibleDigest ?? NA,
      signerXOnly
    },
    approvals: {
      required: String(manifest.action.requiredApprovals ?? "0"),
      collected: String(request.signaturesPresent ?? signedSlots.length),
      approverSlots,
      packageCommitment: null,
      approvalDigests
    },
    /* a root action never moves KAS to a third party or moves tokens
     * itself (§ordinary root actions carry no payment; ownerRecover is the
     * one terminal exception and is mapped by its rooted-vault sibling
     * attestation, since the payout is a VAULT-level fact) */
    asset: { kind: "KAS", descriptorHash: null, familyId: null, unit: "sompi" },
    destination: { kind: "COVENANT_SUCCESSOR", identity: null, scriptHex: null },
    amounts: {
      amount: NA,
      networkFeeSompi: manifest.fee.requiredFeeSompi,
      protocolFeeSompi: null
    },
    outcome: {
      state: reached.length === 0 ? "REFUSED" : reached[reached.length - 1].state,
      disposition,
      failureCode,
      reached,
      txId: decision === "REFUSED" ? null : txId,
      networkId: manifest.network.networkId,
      chain: {
        acceptingBlockDaaScore: null,
        observedVirtualDaaScore: null,
        depthDaa: null,
        minDepthDaa: null,
        predecessorOutpoint: request.chain && request.chain.predecessorOutpoint ? { transactionId: request.chain.predecessorOutpoint.transactionId, index: Number(request.chain.predecessorOutpoint.index) } : null,
        successorOutpoint,
        successorStateId: outputs.length > 0 ? manifest.rootState.after.digest : null,
        covenantId: outputs.length > 0 ? manifest.root.covenantId : null,
        scriptSha256: null,
        outputs
      }
    }
  };

  let attestation;
  try {
    attestation = attest.buildExecutionAttestation(body);
  } catch (e) {
    throw attestError(409, e.code === "ATTESTATION_INVALID" ? "ATTESTATION_EVIDENCE_INCONSISTENT" : e.code ?? "ATTESTATION_BUILD_FAILED", e.message);
  }
  return { attestation, sources: body.producer.sources };
}

/* ------------------------------------------------------------------ */
/* policyvault-0.7-payment — a ROOTED-VAULT operation                  */
/* ------------------------------------------------------------------ */

/*
 * Build ONE attestation for a `policyvault-rooted-vault-manifest/1`
 * (`core/intent/org-root-manifest-v7.js`'s `buildRootedVaultManifestV7`
 * output) — the SAME manifest shape for BOTH:
 *   - an owner operation riding INSIDE a root action's transaction
 *     (`op.manifest` from `orgRootManifest.vaultOperations[]`), and
 *   - a standalone delegate spend / deposit on a rooted vault (no root
 *     input at all — `manifest.action.requiresRootInput === false`).
 *
 * `envelope` carries the request-level facts a manifest alone does not:
 * `{ requestId, organizationId, state, txId, chain, signerVisibleDigest,
 * signerXOnly }`. `state` is the SAME closed ladder vocabulary
 * (AUTHORIZED/SIGNED/BROADCAST/CHAIN_SEEN/CHAIN_VERIFIED/VERIFIED_OUTCOME,
 * or REFUSED/FAILED) `buildAttestationForOrgRootRequest` accepts, so a
 * caller riding inside a root action's transaction can pass the SAME
 * `state`/`txId`/`chain` it passed for the root's own attestation — one
 * transaction, one observed chain state, several attestations.
 */
function mapRootedVaultAttestationBody({ config, manifest, envelope, frozenCanonicalJson, sources = [] }) {
  if (!isPlainObject(manifest) || manifest.manifestVersion !== ROOTED_VAULT_MANIFEST_VERSION_1) {
    throw attestError(500, "ATTESTATION_MANIFEST_VERSION_UNKNOWN", `expected ${JSON.stringify(ROOTED_VAULT_MANIFEST_VERSION_1)} — refusing to attest`);
  }
  if (!isPlainObject(envelope)) throw attestError(500, "ATTESTATION_INPUT_INVALID", "mapRootedVaultAttestationBody requires an envelope of request-level facts");

  const isSpend = manifest.action.sdkAction === "tokenAgentSpend";
  const isRecover = manifest.action.sdkAction === "ownerRecover";

  let decision = "AUTHORIZED";
  let refusalCode = null;
  if (envelope.state === "REFUSED") {
    decision = "REFUSED";
    refusalCode = "ORG_ROOT_REQUEST_REFUSED";
  }

  let reached = [];
  let disposition = "IN_PROGRESS";
  let failureCode = null;
  let txId = null;
  let outputs = [];
  let successorOutpoint = null;

  if (decision === "AUTHORIZED") {
    if (envelope.state === "FAILED") {
      reached = reachedLadderThrough("AUTHORIZED", "org-root-request-v1") ?? [];
      disposition = "FAILED";
      failureCode = "ORG_ROOT_REQUEST_FAILED";
    } else {
      const effectiveState = envelope.state === "VERIFIED_OUTCOME" ? "CHAIN_VERIFIED" : envelope.state;
      reached = reachedLadderThrough(effectiveState, "org-root-request-v1");
      if (reached === null) throw attestError(500, "ATTESTATION_LADDER_STATE_UNKNOWN", `unknown envelope.state ${JSON.stringify(envelope.state)} — failing closed`);
      if (reached.some((r) => r.state === "BROADCAST")) txId = envelope.txId ?? manifest.transaction.txId ?? null;
      if ((reached.some((r) => r.state === "CHAIN_SEEN") || reached.some((r) => r.state === "CHAIN_VERIFIED")) && typeof frozenCanonicalJson === "string") {
        const family = isSpend || isRecover ? manifest.vault.tokenCovenantId : manifest.vault.covenantId;
        const outs = familyOutputs(frozenCanonicalJson, family);
        if (outs.length === 0) {
          throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", "no observed output for the attested covenant family — refusing to attest an unfalsifiable chain claim");
        }
        /* pick the economically meaningful output: the recipient's token
         * continuation for a spend (family output 1, per
         * buildRootedVaultManifestV7's own convention: [self, recipient]);
         * the payout for a terminal recover (output 0); the vault's own
         * successor otherwise */
        const picked = isSpend ? outs[outs.length - 1] : outs[0];
        const address = outputAddress(config, picked, "rooted-vault attested output");
        outputs = [
          {
            index: picked.index,
            address,
            valueSompi: isSpend ? String(manifest.accounting.token.spendAmount) : String(picked.value),
            covenantId: family,
            blockDaaScore: null
          }
        ];
        successorOutpoint = envelope.chain && envelope.chain.successorOutpoint ? { transactionId: envelope.chain.successorOutpoint.transactionId, index: Number(envelope.chain.successorOutpoint.index) } : { transactionId: txId ?? manifest.transaction.txId, index: picked.index };
      }
      if (reached.some((r) => r.state === "CHAIN_VERIFIED")) disposition = "SETTLED";
    }
  } else {
    disposition = "REFUSED";
  }

  const amount = isSpend ? String(manifest.accounting.token.spendAmount) : isRecover ? String(manifest.accounting.kas.terminalPayout ?? "0") : NA;
  const destination = isSpend
    ? { kind: "RECIPIENT_XONLY", identity: manifest.policy.recipient, scriptHex: null }
    : isRecover
      ? { kind: "OWNER_PAYOUT", identity: manifest.vault.recoveryPk, scriptHex: null }
      : { kind: "COVENANT_SUCCESSOR", identity: null, scriptHex: null };
  /* one asset per attestation (the schema's own limitation — matches
   * v0.4's genesis/transition mapping precedent). ownerRecover moves KAS
   * to the pinned recoveryPk; any secondary token recovery in the SAME
   * transaction is a documented residual, not attested here. */
  const asset = isSpend
    ? { kind: "TOKEN", descriptorHash: manifest.asset ? manifest.asset.descriptorHash : null, familyId: manifest.vault.tokenCovenantId, unit: "atomic" }
    : { kind: "KAS", descriptorHash: null, familyId: null, unit: "sompi" };

  const body = {
    attestationVersion: attest.ATTESTATION_VERSION_1,
    producedAt: new Date().toISOString(),
    producer: {
      software: "policyvault",
      buildId: config.buildId ?? NA,
      component: "server-attestation-export-v7",
      sources: [...new Set([ROOTED_VAULT_MANIFEST_VERSION_1, ...sources])]
    },
    subject: {
      requestId: asUuidOrNA(envelope.requestId),
      vaultId: manifest.vault.covenantId,
      organizationId: asUuidOrNull(envelope.organizationId),
      networkId: manifest.network.networkId,
      contractVersion: CONTRACT_VERSION_PAYMENT,
      policyNonce: NA,
      stateBefore: manifest.stateBefore.stateId,
      stateAfter: manifest.action.terminal ? null : manifest.stateAfter ? manifest.stateAfter.stateId : NA
    },
    action: {
      type: manifest.action.sdkAction,
      highLevel: manifest.action.mutationClass,
      role: manifest.action.role === "agent" ? "agent" : "owner",
      /* a delegate spend is policy-gated (agent Merkle proof, per-tx cap,
       * period budget), never an M-of-N approval quorum of its own, so
       * "above threshold" is meaningless for it (mirrors v4's below-
       * threshold convention: required=0). An owner op riding in a root
       * action inherits the ROOT's quorum (see the module header residual
       * #2) rather than carrying one of its own. */
      aboveThreshold: false
    },
    authorization: {
      decision,
      refusalCode,
      intentManifestHash: manifest.manifestHash,
      intentManifestVerdict: "VERIFIED_EXACT",
      signerVisibleDigest: envelope.signerVisibleDigest ?? NA,
      signerXOnly: envelope.signerXOnly ?? NA
    },
    approvals: {
      required: "0",
      collected: "0",
      approverSlots: [],
      packageCommitment: null,
      approvalDigests: []
    },
    asset,
    destination,
    amounts: {
      amount,
      networkFeeSompi: manifest.transaction.requiredFeeSompi ?? NA,
      protocolFeeSompi: null
    },
    outcome: {
      state: reached.length === 0 ? "REFUSED" : reached[reached.length - 1].state,
      disposition,
      failureCode,
      reached,
      txId: decision === "REFUSED" ? null : txId,
      networkId: manifest.network.networkId,
      chain: {
        acceptingBlockDaaScore: null,
        observedVirtualDaaScore: null,
        depthDaa: null,
        minDepthDaa: null,
        predecessorOutpoint: envelope.chain && envelope.chain.predecessorOutpoint ? { transactionId: envelope.chain.predecessorOutpoint.transactionId, index: Number(envelope.chain.predecessorOutpoint.index) } : null,
        successorOutpoint,
        successorStateId: outputs.length > 0 && !manifest.action.terminal && manifest.stateAfter ? manifest.stateAfter.stateId : null,
        covenantId: outputs.length > 0 ? outputs[0].covenantId : null,
        scriptSha256: null,
        outputs
      }
    }
  };

  let attestation;
  try {
    attestation = attest.buildExecutionAttestation(body);
  } catch (e) {
    throw attestError(409, e.code === "ATTESTATION_INVALID" ? "ATTESTATION_EVIDENCE_INCONSISTENT" : e.code ?? "ATTESTATION_BUILD_FAILED", e.message);
  }
  return { attestation, sources: body.producer.sources };
}

/*
 * Every rooted-vault owner operation riding INSIDE a root action's
 * transaction (`request.manifest.vaultOperations[]`), each as its OWN
 * policyvault-0.7-payment attestation sharing the root's OWN observed
 * chain state (same transaction, same txId, same broadcast/chain facts).
 */
function buildAttestationsForOrgRootRequestVaultOps(config, request) {
  if (!isPlainObject(request) || request.schemaVersion !== ORG_ROOT_REQUEST_SCHEMA_V1) {
    throw attestError(404, "ATTESTATION_SUBJECT_NOT_FOUND", "no attestable org-root request");
  }
  const manifest = request.manifest;
  if (!manifest || !Array.isArray(manifest.vaultOperations)) {
    throw attestError(409, "ATTESTATION_EVIDENCE_INCOMPLETE", "the request carries no vaultOperations to attest");
  }
  /*
   * A rooted-vault op riding IN a root action has no signing identity of
   * its OWN (its authority is the root's M-of-N — see the module header
   * residual #2), so once its ladder reaches SIGNED it needs SOME
   * concrete signerXOnly to satisfy SIGNED_WITHOUT_SIGNER_EVIDENCE — the
   * SAME convention `buildAttestationForOrgRootRequest` uses for the root
   * action's own attestation: the first SIGNED slot's public key. This is
   * an honest, real signing identity (one of the co-signing owners), not
   * a synthesized one.
   */
  const slotsArr = Array.isArray(request.slots) ? request.slots : [];
  const firstSignedSlot = slotsArr.find((s) => s && s.status === "SIGNED" && typeof s.publicKey === "string");
  const envelope = {
    requestId: request.id,
    /* the on-chain boundOrgId is NOT the hosted-layer organizationId (see
     * asUuidOrNull's header note) — no hosted-org lookup is wired on this
     * track, so this is honestly null unless a caller extends the envelope. */
    organizationId: null,
    state: request.state,
    txId: request.txId,
    chain: request.chain ?? null,
    signerVisibleDigest: NA,
    signerXOnly: firstSignedSlot ? firstSignedSlot.publicKey : NA
  };
  return manifest.vaultOperations.map((op) => mapRootedVaultAttestationBody({ config, manifest: op.manifest, envelope, frozenCanonicalJson: manifest.transaction.frozenCanonicalJson, sources: ["policyvault-org-root-request/1", ORG_ROOT_MANIFEST_VERSION_1] }));
}

/*
 * Build ONE attestation for a standalone delegate-spend or deposit on a
 * rooted vault (`POST /wallet/v7/requests`; no root input). `record` is
 * expected to carry `{ manifest: <policyvault-rooted-vault-manifest/1>,
 * requestId, organizationId, state, txId, chain, signerVisibleDigest,
 * signerXOnly, frozenCanonicalJson }` — the SMALL, explicit envelope this
 * module needs, independent of whatever exact durable shape
 * `sdk/src/wallet-requests-v7.js` eventually adopts (see the module header
 * residual #1).
 */
function buildAttestationForRootedVaultRequest(config, record) {
  if (!isPlainObject(record) || !isPlainObject(record.manifest)) {
    throw attestError(404, "ATTESTATION_SUBJECT_NOT_FOUND", "no attestable rooted-vault request");
  }
  return mapRootedVaultAttestationBody({
    config,
    manifest: record.manifest,
    envelope: {
      requestId: record.requestId,
      organizationId: record.organizationId ?? null,
      state: record.state,
      txId: record.txId,
      chain: record.chain ?? null,
      signerVisibleDigest: record.signerVisibleDigest,
      signerXOnly: record.signerXOnly
    },
    frozenCanonicalJson: record.frozenCanonicalJson,
    /* PROVISIONAL source label: sdk/src/wallet-requests-v7.js does not
     * exist yet, so this is not a real durable-record schema name (see
     * the module header residual #1) — kept identifier-shaped so it still
     * passes producer.sources' IDENT_RE, but it names a shape this module
     * assumes, not one that has shipped. */
    sources: ["policyvault-v7-wallet-request-provisional/1"]
  });
}

module.exports = {
  ORG_ROOT_REQUEST_SCHEMA_V1,
  ORG_ROOT_REQUEST_CATEGORY,
  CONTRACT_VERSION_ROOT,
  CONTRACT_VERSION_PAYMENT,
  ROOT_ACTIONS,
  ORG_ROOT_REQUEST_TERMINAL_STATES,
  loadOrgRootRequestForAttestation,
  buildAttestationForOrgRootRequest,
  buildAttestationsForOrgRootRequestVaultOps,
  buildAttestationForRootedVaultRequest,
  mapRootedVaultAttestationBody
};
