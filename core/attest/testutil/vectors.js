"use strict";

/*
 * TEST VECTORS for policyvault-execution-attestation/1.
 *
 * HARNESS CODE (testutil/) — exempt from the portability rules that bind
 * core/attest/*.js: it reads the repository's live-testnet evidence file
 * from disk so the POSITIVE vector is built from facts that were actually
 * observed on a real node, not from numbers invented for a test.
 *
 * Source: docs/testnet-v6-atomic-evidence.json (read-only; NEVER written)
 * — the definitive run-2 transcript of the v0.6 atomic-composability live
 * testnet-10 proof. The SELL leg is the richest single record in the repo
 * that carries the whole ladder AUTHORIZED -> SIGNED -> BROADCAST ->
 * CHAIN_VERIFIED -> VERIFIED_OUTCOME with exact outputs, so it is the
 * natural positive vector.
 *
 * HONESTY RULES OBSERVED WHILE MAPPING THAT TRANSCRIPT
 *  - the transcript is NOT a hosted durable record: it carries no
 *    requestId, no policy nonce, no build id, and no signer-visible
 *    digest, so those fields are the explicit NOT_AVAILABLE sentinel —
 *    never invented;
 *  - the transcript records no post-acceptance virtual DAA score, so
 *    observedVirtualDaaScore / depthDaa / minDepthDaa are null rather
 *    than back-computed;
 *  - the agent x-only key is present only inside the transcript's own
 *    explanation lines, so it is extracted with a strict 64-hex regex and
 *    asserted, never guessed;
 *  - the v0.6 controller's covenant id is used as the vault identity,
 *    which is exactly what that covenant generation's live tool means by
 *    "the vault".
 */

const fs = require("fs");
const path = require("path");

const { buildExecutionAttestation } = require("../record");
const { ATTESTATION_VERSION_1, NOT_AVAILABLE } = require("../schema");

const EVIDENCE_PATH = path.join(__dirname, "..", "..", "..", "docs", "testnet-v6-atomic-evidence.json");

function loadEvidence() {
  const doc = JSON.parse(fs.readFileSync(EVIDENCE_PATH, "utf8"));
  if (doc.schema !== "policyvault-testnet-v6-atomic-evidence/1") {
    throw new Error(`unexpected evidence schema ${doc.schema} — refusing to build a vector from it`);
  }
  return doc;
}

const step = (doc, name) => {
  const s = doc.steps.find((x) => x.step === name);
  if (!s) throw new Error(`evidence transcript has no step ${name}`);
  return s;
};

function agentXOnlyFromExplanation(authorized) {
  const line = (authorized.explanation ?? []).find((l) => l.startsWith("AGENT "));
  const m = line && /^AGENT ([0-9a-f]{64}):/.exec(line);
  if (!m) throw new Error("could not extract the agent x-only key from the transcript explanation");
  return m[1];
}

/*
 * The live-testnet SELL leg as a policyvault-execution-attestation/1
 * record. Deterministic: same file in, same record (and same record
 * hash) out, on any machine.
 */
function liveTestnetSellAttestation() {
  const doc = loadEvidence();
  const authorized = step(doc, "atomic-sell:AUTHORIZED");
  const signed = step(doc, "atomic-sell:SIGNED");
  const chainVerified = step(doc, "atomic-sell:CHAIN_VERIFIED");
  const outcome = step(doc, "atomic-sell:VERIFIED_OUTCOME");
  const controller = step(doc, "controller");
  const descriptor = step(doc, "descriptor+profile+policy");

  const txId = outcome.txId;
  const accepting = chainVerified.verified[0].blockDaaScore;
  const controllerConsumed = chainVerified.consumed.find((c) => c.transactionId === doc.summary.controllerId) ?? chainVerified.consumed[1];

  return buildExecutionAttestation({
    attestationVersion: ATTESTATION_VERSION_1,
    producedAt: outcome.at,
    producer: {
      software: "policyvault",
      buildId: NOT_AVAILABLE,
      component: "testnet-v6-atomic-proof-transcript",
      sources: [doc.schema]
    },
    subject: {
      requestId: NOT_AVAILABLE, // the live proof tool mints no hosted request
      vaultId: doc.summary.controllerId,
      organizationId: null,
      networkId: doc.network.networkId,
      contractVersion: controller.contractVersion,
      policyNonce: NOT_AVAILABLE,
      stateBefore: controller.stateId,
      stateAfter: outcome.successorStateId
    },
    action: { type: "tokenAtomicSell", highLevel: null, role: "agent", aboveThreshold: false },
    authorization: {
      decision: "AUTHORIZED",
      refusalCode: null,
      intentManifestHash: authorized.manifestHash,
      intentManifestVerdict: "VERIFIED_EXACT",
      signerVisibleDigest: NOT_AVAILABLE, // the transcript records the sighash TYPE, not the digest
      signerXOnly: agentXOnlyFromExplanation(authorized)
    },
    approvals: { required: "0", collected: "0", approverSlots: [], packageCommitment: null, approvalDigests: [] },
    asset: { kind: "TOKEN", descriptorHash: descriptor.descriptorHash, familyId: descriptor.familyId, unit: "atomic" },
    destination: { kind: "COVENANT_SUCCESSOR", identity: null, scriptHex: null },
    amounts: {
      amount: authorized.quote.amountIn,
      networkFeeSompi: authorized.economics.networkFeeSompi,
      protocolFeeSompi: authorized.economics.protocolFeeSompi
    },
    outcome: {
      state: "VERIFIED_OUTCOME",
      disposition: "SETTLED",
      failureCode: null,
      reached: [
        { state: "AUTHORIZED", source: "intent-manifest-verification", note: `${authorized.checks} manifest checks passed` },
        { state: "SIGNED", source: "external-signer", note: `signed at DAA ${signed.signedAtDaa}, pre-sign deadline ${signed.deadlineDaa}` },
        { state: "BROADCAST", source: "node-submit", note: "the node returned the frozen transaction id" },
        { state: "CHAIN_SEEN", source: "implied-by-chain-verified", note: "the exact expected outputs were read back from the node" },
        { state: "CHAIN_VERIFIED", source: "utxo-readback", note: "5 outputs matched exactly; both predecessor outpoints consumed" },
        { state: "VERIFIED_OUTCOME", source: "economic-reconciliation", note: "token conservation held and the KAS principal moved by exactly the quoted net proceeds" }
      ],
      txId,
      networkId: doc.network.networkId,
      chain: {
        acceptingBlockDaaScore: accepting,
        observedVirtualDaaScore: null, // the transcript records no post-acceptance virtual DAA
        depthDaa: null,
        minDepthDaa: null,
        predecessorOutpoint: { transactionId: controllerConsumed.transactionId, index: controllerConsumed.index },
        successorOutpoint: { transactionId: txId, index: 0 },
        successorStateId: outcome.successorStateId,
        covenantId: doc.summary.controllerId,
        scriptSha256: null, // the transcript pins the GENESIS script hash, not the successor's
        outputs: chainVerified.verified.map((v) => ({
          index: v.index,
          address: v.address,
          valueSompi: v.value,
          covenantId: v.covenantId ?? null,
          blockDaaScore: v.blockDaaScore
        }))
      }
    }
  });
}

/*
 * A fully-populated SYNTHETIC vector: a KAS agentSpend on a v0.4.1 vault
 * with a real M-of-N quorum, depth arithmetic, and a signer-visible
 * digest — the fields the live transcript legitimately lacks. Fixed
 * values only; nothing here is chain evidence and nothing here is
 * presented as such.
 */
const H = (b) => b.repeat(32);
function syntheticSpendAttestation(overrides = {}) {
  const body = {
    attestationVersion: ATTESTATION_VERSION_1,
    producedAt: "2026-09-03T12:00:00.000Z",
    producer: { software: "policyvault", buildId: "test-build", component: "attestation-export", sources: ["policyvault-wallet-request/v4", "policyvault-intent-manifest-record/v1", "policyvault-receipt/v1"] },
    subject: {
      requestId: "11111111-2222-4333-8444-555555555555",
      vaultId: H("a1"),
      organizationId: null,
      networkId: "testnet-10",
      contractVersion: "policyvault-0.4.1",
      policyNonce: "7",
      stateBefore: H("b1"),
      stateAfter: H("b2")
    },
    action: { type: "agentSpend", highLevel: "pay", role: "agent", aboveThreshold: true },
    authorization: {
      decision: "AUTHORIZED",
      refusalCode: null,
      intentManifestHash: H("c1"),
      intentManifestVerdict: "VERIFIED_EXACT",
      signerVisibleDigest: H("d1"),
      signerXOnly: H("e1")
    },
    approvals: {
      required: "2",
      collected: "2",
      approverSlots: [H("f1"), H("f2"), H("f3")],
      packageCommitment: H("09"),
      approvalDigests: [
        { slot: "0", approverXOnly: H("f1"), signatureDigest: H("11") },
        { slot: "1", approverXOnly: H("f2"), signatureDigest: H("12") }
      ]
    },
    asset: { kind: "KAS", descriptorHash: null, familyId: null, unit: "sompi" },
    destination: { kind: "RECIPIENT_XONLY", identity: H("aa"), scriptHex: null },
    amounts: { amount: "1500000000", networkFeeSompi: "8018200", protocolFeeSompi: null },
    outcome: {
      state: "CHAIN_VERIFIED",
      disposition: "SETTLED",
      failureCode: null,
      reached: [
        { state: "AUTHORIZED", source: "wallet-request-v4", note: null },
        { state: "SIGNED", source: "external-signer", note: null },
        { state: "BROADCAST", source: "node-submit", note: null },
        { state: "CHAIN_SEEN", source: "implied-by-chain-verified", note: null },
        { state: "CHAIN_VERIFIED", source: "receipt-v1", note: null }
      ],
      txId: H("7a"),
      networkId: "testnet-10",
      chain: {
        acceptingBlockDaaScore: "560488141",
        observedVirtualDaaScore: "560488241",
        depthDaa: "100",
        minDepthDaa: "12",
        predecessorOutpoint: { transactionId: H("6a"), index: 0 },
        successorOutpoint: { transactionId: H("7a"), index: 0 },
        successorStateId: H("b2"),
        covenantId: H("cc"),
        scriptSha256: H("dd"),
        outputs: [
          { index: 0, address: "kaspatest:qqsuccessor", valueSompi: "98500000000", covenantId: H("cc"), blockDaaScore: "560488141" },
          { index: 1, address: "kaspatest:qqrecipient", valueSompi: "1500000000", covenantId: null, blockDaaScore: "560488141" }
        ]
      }
    }
  };
  return buildExecutionAttestation(deepMerge(body, overrides));
}

/*
 * A REFUSED vector: PolicyVault deterministically declined to authorize,
 * nothing was signed, nothing was broadcast, no transaction exists. The
 * refusal is itself evidence and is exportable as such.
 */
function refusedAttestation(overrides = {}) {
  const body = {
    attestationVersion: ATTESTATION_VERSION_1,
    producedAt: "2026-09-03T12:05:00.000Z",
    producer: { software: "policyvault", buildId: "test-build", component: "attestation-export", sources: ["policyvault-wallet-request/v4"] },
    subject: {
      requestId: "99999999-8888-4777-8666-555555555555",
      vaultId: H("a1"),
      organizationId: null,
      networkId: "testnet-10",
      contractVersion: "policyvault-0.4.1",
      policyNonce: "7",
      stateBefore: H("b1"),
      stateAfter: null
    },
    action: { type: "agentSpend", highLevel: "pay", role: "agent", aboveThreshold: false },
    authorization: {
      decision: "REFUSED",
      refusalCode: "AGENT_CAP_EXCEEDED",
      intentManifestHash: NOT_AVAILABLE,
      intentManifestVerdict: NOT_AVAILABLE,
      signerVisibleDigest: NOT_AVAILABLE,
      signerXOnly: NOT_AVAILABLE
    },
    approvals: { required: "0", collected: "0", approverSlots: [], packageCommitment: null, approvalDigests: [] },
    asset: { kind: "KAS", descriptorHash: null, familyId: null, unit: "sompi" },
    destination: { kind: "RECIPIENT_XONLY", identity: H("aa"), scriptHex: null },
    amounts: { amount: "9900000000000", networkFeeSompi: NOT_AVAILABLE, protocolFeeSompi: null },
    outcome: {
      state: "REFUSED",
      disposition: "REFUSED",
      failureCode: null,
      reached: [],
      txId: null,
      networkId: "testnet-10",
      chain: {
        acceptingBlockDaaScore: null,
        observedVirtualDaaScore: null,
        depthDaa: null,
        minDepthDaa: null,
        predecessorOutpoint: null,
        successorOutpoint: null,
        successorStateId: null,
        covenantId: null,
        scriptSha256: null,
        outputs: []
      }
    }
  };
  return buildExecutionAttestation(deepMerge(body, overrides));
}

/* Test-only merge so a vector can be perturbed field-by-field. */
function deepMerge(base, patch) {
  if (patch === undefined) return base;
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) return patch;
  const out = Array.isArray(base) ? [...base] : { ...base };
  for (const [k, v] of Object.entries(patch)) {
    out[k] = k in out && !Array.isArray(v) && v !== null && typeof v === "object" ? deepMerge(out[k], v) : v;
  }
  return out;
}

/* Deep clone that drops frozen-ness, so tamper tests can mutate. */
const clone = (v) => JSON.parse(JSON.stringify(v));

module.exports = { EVIDENCE_PATH, loadEvidence, liveTestnetSellAttestation, syntheticSpendAttestation, refusedAttestation, deepMerge, clone, H };
