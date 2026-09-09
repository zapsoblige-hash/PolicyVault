"use strict";

/*
 * REAL, SELF-VERIFYING `policyvault-token-intent-manifest/1` (v0.5)
 * fixtures for web/test/token-vault-ui.test.js. Same discipline as
 * web/test/fixtures/hd-manifest-fixtures.js: every byte below is produced
 * by the SAME pinned core codecs (core/assets, core/model/token-amounts)
 * the real verifier recomputes with, so this fixture is internally
 * consistent BY CONSTRUCTION — `buildDepositFixture` asserts VERIFIED
 * before returning.
 *
 * Scope: a v0.5 `tokenDeposit` (the user's own wallet key signs the token
 * input directly; the SIMPLEST of the seven v0.5 actions and, unlike
 * `tokenAgentSpend`, needs no agent-Merkle proof or recipient allowlist to
 * construct) — enough to exercise token-vault-ui.js's full
 * verify-then-render pipeline (core.intentRouter.verifyManifest ->
 * core.tokenExplain.explainTokenIntent) against a REAL manifest, the same
 * pipeline `tokenAgentSpend`/owner-op manifests also go through. A full
 * `tokenAgentSpend` fixture additionally requires a real KCC20 P2SH
 * redeem/continuation reconstruction (core/assets/kcc20.js) and an agent
 * Merkle proof (core/model/agent-merkle-v5.js); this module does not
 * attempt that construction — the refusal/DO-NOT-SIGN paths for that
 * action are covered with a deliberately malformed manifest instead
 * (still a REAL manifestVersion/router dispatch, just not a positive
 * VERIFIED case), which is sufficient to prove the review pipeline treats
 * every action name identically.
 */

const path = require("path");
const REPO = path.join(__dirname, "..", "..", "..");
const assets = require(path.join(REPO, "core/assets/index.js"));
const { kcc20 } = assets;
const { buildTokenIntentManifest, verifyTokenIntentManifest } = require(path.join(REPO, "core/intent/token-manifest-v5.js"));

const HEX = (b, n) => b.toString(16).padStart(2, "0").repeat(n);

function buildDescriptor() {
  const prefix = Buffer.alloc(10, 0x11);
  const suffix = Buffer.alloc(12, 0x22);
  const templateVmHash = kcc20.templateVmHashHex(prefix, suffix);
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: HEX(0xa1, 32),
    displayName: "Test Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: HEX(0xf1, 32),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: templateVmHash, prefixLen: 10, suffixLen: 12, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 8,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  return { descriptor, templateVmHash };
}

/*
 * A REAL, VERIFIED v0.5 tokenDeposit manifest. `depositAmount` (atomic
 * units, default 2000) is deposited whole (no remainder) at zero declared
 * network fee (the manifest layer's own arithmetic permits this: fee is
 * simply totalIn - totalOut, and this fixture sets them equal — it is not
 * a claim about a realistic production fee, only an internally consistent
 * one for exercising the review UI).
 */
function buildDepositFixture({ depositAmount = "2000" } = {}) {
  const { descriptor, templateVmHash } = buildDescriptor();
  const validated = assets.validateAssetDescriptor(descriptor);
  const descriptorHash = assets.computeDescriptorHash(validated);

  const controllerCovenantId = HEX(0xc1, 32);
  const ownerPk = HEX(0x0a, 32);
  const vaultId = HEX(0x1a, 32);
  const userPk = HEX(0x0b, 32);

  const build = {
    contractVersion: "policyvault-0.5",
    kind: "tokenDeposit",
    networkId: "testnet-10",
    txId: HEX(0xbb, 32),
    frozenCanonicalJson: JSON.stringify({
      inputs: [{ utxo: { covenantId: descriptor.tokenCovenantId, amount: depositAmount, scriptPublicKey: { scriptHex: `aa20${"33".repeat(32)}87` } }, computeBudget: 90 }],
      outputs: [{ value: depositAmount, covenant: { covenantId: descriptor.tokenCovenantId } }]
    }),
    requiredFeeSompi: "0",
    frozen: { inputs: [{ computeBudget: 90 }] },
    controller: {
      covenantId: controllerCovenantId,
      template: { vaultId, owner: ownerPk, descriptorHash, tokenCovenantId: descriptor.tokenCovenantId, templateVmHash, templatePrefixLen: 10, templateStateLen: 46, templateSuffixLen: 12 }
    },
    asset: { templateIndex: 0 },
    accounting: {
      token: { positionBefore: depositAmount, deposit: depositAmount, remainderToUser: "0" },
      /* fee/positionKas are the only fields verifyTokenIntentManifest's
       * verifyDeposit() re-checks; externalIn/externalOut/depositCarryKas/
       * remainderCarryKas are unverified display-only fields
       * core/explain/token-explain.js's deposit section also reads —
       * carried here so the review renders, not because they are proven. */
      kas: { fee: "0", positionKas: depositAmount, externalIn: "0", externalOut: "0", depositCarryKas: depositAmount, remainderCarryKas: "0" }
    },
    userPk,
    tokenNewStates: [{ ownerIdentifier: controllerCovenantId, identifierType: 2, amount: depositAmount, isMinter: false }]
  };

  const manifest = buildTokenIntentManifest({ build, descriptor });
  const verification = verifyTokenIntentManifest({ manifest, descriptor });
  if (verification.verdict !== "VERIFIED") {
    throw new Error(`token-manifest-fixtures: deposit fixture failed to self-verify: ${JSON.stringify(verification.failures)}`);
  }
  return { manifest, verification, descriptor, validated };
}

module.exports = { buildDepositFixture, buildDescriptor };
