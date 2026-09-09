"use strict";

/*
 * v0.7 ORGANIZATIONAL ROOT test vector (Wave 2, Track G) — a positive
 * `policyvault-execution-attestation/1` record built read-only from the
 * REAL testnet-10 lifecycle transcript, mirroring exactly the pattern
 * `vectors.js`'s `liveTestnetSellAttestation()` already establishes for
 * v0.6 (same file, same discipline, kept in its own sibling file so a
 * v0.6 change never touches this one and vice versa).
 *
 * HARNESS CODE (testutil/) — exempt from core/attest's purity rules: it
 * reads the repository's live-testnet evidence file from disk so the
 * vector is built from facts a real node actually returned, never from
 * numbers invented for a test.
 *
 * Source: docs/testnet-v7-org-root-evidence.json — the real v0.7
 * lifecycle run (118 steps, 9 negative validations, 2 age proofs). Step
 * "19-vault-owner-recover-terminal" is the LAST step of the run: it
 * terminates the ROOTED VAULT (a payout to the genesis-pinned recoveryPk)
 * while the ORGANIZATIONAL ROOT itself continues under an ordinary
 * "authorize" 2-of-N quorum (owner-recover's root path never changes the
 * owner set — core/model/owner-set-v7 ROOT_ACTIONS_V7.authorize is
 * AUTHORITY-NEUTRAL, `setMayChange: false`). The transcript's own
 * `summary.finalRootOutpoint` / `VERIFIED_OUTCOME.rootStillLive` name this
 * EXACT root successor outpoint as still live at the end of the run,
 * which is what makes it the natural candidate for a genuine LIVE
 * RE-CHECK: this vector's ONE declared observed output is the root's own
 * continuation, and a reader who runs `tools/attestation-verify.js
 * --chain` against ANY synced testnet-10 node can independently confirm
 * or (if the outpoint has since been spent by a later, unrecorded
 * transition) honestly fail to confirm it — never contradict it, since
 * the transcript's own facts are real.
 *
 * HONESTY RULES OBSERVED WHILE MAPPING THIS TRANSCRIPT
 *  - VERIFIED_OUTCOME is deliberately NOT claimed: this vector attests to
 *    the ROOT's continuation (a covenant-identity + value fact), not to
 *    an economic outcome the transcript would need to separately prove
 *    conservation for — the ladder caps at CHAIN_VERIFIED;
 *  - the transcript's per-step JSON does not name which OWNER identity
 *    each of "signedSlots: [1,2]" corresponds to, so `signerXOnly` is the
 *    first ACTIVE owner key from `summary.finalRootState.owners` (a REAL
 *    on-chain key, honestly labeled as "one co-signing owner", the SAME
 *    convention `server/src/attestations-v7.js` uses) rather than a
 *    fabricated identity;
 *  - approval EVIDENCE (required/collected/digests) is NOT reconstructed
 *    from this transcript — exactly the same choice `vectors.js`'s v0.6
 *    vector makes for its own SELL leg, for the same reason: the
 *    transcript does not carry per-approval response-envelope hashes,
 *    and a `collected` count with zero digests would itself be an
 *    internally-inconsistent record;
 *  - depth arithmetic uses the run's OWN recorded
 *    `network.virtualDaaScoreAtEnd` against this step's own
 *    `blockDaaScore` — both real recorded numbers, never back-computed
 *    from a formula.
 */

const fs = require("fs");
const path = require("path");

const { buildExecutionAttestation } = require("../record");
const { ATTESTATION_VERSION_1, NOT_AVAILABLE } = require("../schema");

const EVIDENCE_PATH = path.join(__dirname, "..", "..", "..", "docs", "testnet-v7-org-root-evidence.json");

function loadEvidenceV7() {
  const doc = JSON.parse(fs.readFileSync(EVIDENCE_PATH, "utf8"));
  if (doc.schema !== "policyvault-testnet-v7-org-root-evidence/1" && typeof doc.schema !== "string") {
    throw new Error(`unexpected v0.7 evidence schema ${doc.schema} — refusing to build a vector from it`);
  }
  return doc;
}

const step = (doc, name) => {
  const s = doc.steps.find((x) => x.step === name);
  if (!s) throw new Error(`v0.7 evidence transcript has no step ${name}`);
  return s;
};

function parseOutpoint(text) {
  const m = /^([0-9a-f]{64}):(\d+)$/.exec(text);
  if (!m) throw new Error(`not an outpoint string: ${JSON.stringify(text)}`);
  return { transactionId: m[1], index: Number(m[2]) };
}

/*
 * The real v0.7 root continuation from step 19 as a
 * policyvault-execution-attestation/1 record, contractVersion
 * policyvault-0.7-root. Deterministic: same evidence file in, same
 * record (and same record hash) out, on any machine.
 */
function liveTestnetV7RootAttestation() {
  const doc = loadEvidenceV7();
  const authorized = step(doc, "19-vault-owner-recover-terminal:AUTHORIZED");
  const signed = step(doc, "19-vault-owner-recover-terminal:SIGNED");
  const chainVerified = step(doc, "19-vault-owner-recover-terminal:CHAIN_VERIFIED");
  const outcome = step(doc, "19-vault-owner-recover-terminal:VERIFIED_OUTCOME");

  const rootOutput = chainVerified.verified.find((v) => v.label === "root successor");
  if (!rootOutput) throw new Error("v0.7 evidence: step 19 CHAIN_VERIFIED carries no root-successor output");
  const rootOutpoint = parseOutpoint(outcome.rootStillLive);
  if (rootOutput.outpoint !== outcome.rootStillLive) {
    throw new Error("v0.7 evidence: the verified root-successor output and rootStillLive disagree — refusing to build a vector from an inconsistent transcript");
  }

  const owners = (doc.summary && doc.summary.finalRootState && doc.summary.finalRootState.owners) || [];
  const signerXOnly = owners.find((k) => typeof k === "string" && !/^0+$/.test(k));
  if (!signerXOnly) throw new Error("v0.7 evidence: no active owner key found in summary.finalRootState.owners");

  const accepting = rootOutput.blockDaaScore;
  const observed = doc.network.virtualDaaScoreAtEnd;
  const depth = (BigInt(observed) - BigInt(accepting)).toString();

  return buildExecutionAttestation({
    attestationVersion: ATTESTATION_VERSION_1,
    producedAt: outcome.at,
    producer: {
      software: "policyvault",
      buildId: NOT_AVAILABLE,
      component: "testnet-v7-org-root-evidence-transcript",
      sources: [typeof doc.schema === "string" ? doc.schema : "policyvault-testnet-v7-org-root-evidence/1"]
    },
    subject: {
      requestId: NOT_AVAILABLE, // the live proof tool mints no hosted request
      vaultId: rootOutput.covenantId, // the ROOT covenant id (this attestation is ABOUT the root's continuation)
      organizationId: null,
      networkId: doc.network.networkId,
      contractVersion: "policyvault-0.7-root",
      policyNonce: NOT_AVAILABLE, // the transcript names the successor STATE DIGEST, not a bare nonce, at this step
      stateBefore: NOT_AVAILABLE,
      stateAfter: authorized.rootAuthority.newStateDigest
    },
    action: { type: authorized.rootAuthority.rootActionName, highLevel: "AUTHORITY-NEUTRAL", role: "owner", aboveThreshold: false },
    authorization: {
      decision: "AUTHORIZED",
      refusalCode: null,
      intentManifestHash: authorized.manifestHash,
      intentManifestVerdict: authorized.manifestVerdict === "VERIFIED" ? "VERIFIED_EXACT" : "REFUSED",
      signerVisibleDigest: NOT_AVAILABLE, // the transcript records the sighash TYPE ("ALL"), not the digest
      signerXOnly
    },
    /* approval evidence is NOT reconstructed from this transcript — see
     * the module header; the SAME choice the v0.6 live vector makes. */
    approvals: { required: "0", collected: "0", approverSlots: [], packageCommitment: null, approvalDigests: [] },
    asset: { kind: "KAS", descriptorHash: null, familyId: null, unit: "sompi" },
    destination: { kind: "COVENANT_SUCCESSOR", identity: null, scriptHex: null },
    amounts: { amount: NOT_AVAILABLE, networkFeeSompi: authorized.feeSompi, protocolFeeSompi: null },
    outcome: {
      /* capped at CHAIN_VERIFIED — this vector claims a covenant-identity
       * + value continuation fact, never an economic VERIFIED_OUTCOME. */
      state: "CHAIN_VERIFIED",
      disposition: "SETTLED",
      failureCode: null,
      reached: [
        { state: "AUTHORIZED", source: "intent-manifest-verification", note: `${authorized.manifestChecks} manifest checks passed` },
        { state: "SIGNED", source: "external-signer", note: `slots ${JSON.stringify(signed.signedSlots)} satisfied ${signed.satisfiedApprovals} of ${authorized.rootAuthority.requiredApprovals} required` },
        { state: "BROADCAST", source: "node-submit", note: "the node returned the frozen transaction id" },
        { state: "CHAIN_SEEN", source: "implied-by-chain-verified", note: "the expected outputs were read back from the node" },
        { state: "CHAIN_VERIFIED", source: "utxo-readback", note: "the root successor matched exactly at the recorded accepting DAA score" }
      ],
      txId: outcome.txId,
      networkId: doc.network.networkId,
      chain: {
        acceptingBlockDaaScore: accepting,
        observedVirtualDaaScore: observed,
        depthDaa: depth,
        minDepthDaa: null,
        predecessorOutpoint: parseOutpoint(authorized.rootAuthority.rootOutpoint),
        successorOutpoint: rootOutpoint,
        successorStateId: authorized.rootAuthority.newStateDigest,
        covenantId: rootOutput.covenantId,
        scriptSha256: null,
        outputs: [
          {
            index: rootOutpoint.index,
            address: rootOutput.address,
            valueSompi: rootOutput.valueSompi,
            covenantId: rootOutput.covenantId,
            blockDaaScore: rootOutput.blockDaaScore
          }
        ]
      }
    }
  });
}

module.exports = { EVIDENCE_PATH, loadEvidenceV7, liveTestnetV7RootAttestation };
