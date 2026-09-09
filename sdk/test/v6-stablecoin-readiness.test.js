"use strict";
/*
 * STABLECOIN READINESS (architecture/conformance evidence only; owner
 * directive 2026-09-03 §12). PolicyVault hard-codes NO stablecoin and keeps
 * NO blessed list: a KCC20-compatible stablecoin is just a configured
 * descriptor whose issuer powers are surfaced VERBATIM, whose exact template
 * is pinned, whose amounts are canonical, and which the owner accepts by
 * pinning its descriptor hash into a controller. Unknown standards fail closed.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv6-stable-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder"));
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV6 } = require("../src/agent-merkle-v6");
const { buildSwapPolicyTreeV6, swapPolicyFromProfileV6 } = require("../src/swap-policy-v6");
const { compilePoolFixtureV6, poolFixtureVenueProfile } = require("../src/swap-pool-fixture-v6");
const { buildV6Transaction } = require("../src/vault-builders-v6");
const { buildSwapIntentManifest, verifySwapIntentManifest } = require("../../core/intent/swap-manifest-v6");

const KAS = 100000000n;

test("no stablecoin is hard-coded and no blessed asset list exists in the v0.6 core/SDK", () => {
  const roots = ["core/model", "core/intent", "core/assets", "sdk/src"].map((r) => path.join(__dirname, "..", "..", r));
  const offenders = [];
  for (const root of roots) {
    for (const f of fs.readdirSync(root)) {
      if (!f.endsWith(".js")) continue;
      const text = fs.readFileSync(path.join(root, f), "utf8");
      if (/\b(USDT|USDC|DAI|tether|circle)\b/i.test(text) || /blessed(Assets|List)|ALLOWED_STABLECOINS|KNOWN_STABLECOINS/.test(text)) offenders.push(`${root}/${f}`);
    }
  }
  assert.deepEqual(offenders, []);
});

test("an issuer-controlled KCC20-compatible descriptor (stablecoin-shaped) flows through the v0.6 swap path with issuer powers surfaced verbatim", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: silverc + pv_call_encoder" }, () => {
  const refProgram = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const issuerPowers = { mint: true, burn: true, freeze: true, blacklist: true, redemptionControl: true, upgradeMigration: false, controllerRotation: false, emergencyControl: true };
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: "5a".repeat(32),
    displayName: "Configured Fiat-Backed Token (example)",
    tokenStandard: "kcc20/1",
    tokenCovenantId: "54".repeat(32),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 6,
    issuerPowers
  };
  const validated = assets.validateAssetDescriptor(descriptor);
  assert.deepEqual(validated.issuerPowers, issuerPowers);
  const template = { owner: "61".repeat(32), vaultId: "44".repeat(32), descriptorHash: assets.computeDescriptorHash(descriptor), tokenCovenantId: "54".repeat(32), templateVmHash: refProgram.templateVmHashBlake2b256, templatePrefixLen: refProgram.geometry.prefixLen, templateStateLen: refProgram.geometry.stateLen, templateSuffixLen: refProgram.geometry.suffixLen };
  const poolState = { kasReserve: (10_000n * KAS).toString(), tokenReserve: "10000", feeBps: "30", nonce: "0" };
  const pool0 = compilePoolFixtureV6({ config, params: { tokenCovenantId: "54".repeat(32), kcc20: { prefixHex: refProgram.prefixHex, suffixHex: refProgram.suffixHex, templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256 }, protocolFeePk: "66".repeat(32), protocolFeeBps: "20", ...poolState } });
  const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId: "50".repeat(32), compiled: pool0 });
  const swapA = swapPolicyFromProfileV6(venueProfile, { maxProtocolFeeKas: (5n * KAS).toString(), sellFloorNum: (9n * KAS / 10n).toString(), sellFloorDen: "1", buyCeilNum: (11n * KAS / 10n).toString(), buyCeilDen: "1", directionMask: "3", destScheme: 0x02 });
  const agentPolicy = { agentPk: "62".repeat(32), tokenMaxPerSpend: "600", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: KAS.toString(), agentMaxCarryKas: (KAS / 4n).toString(), kasMaxPerSwap: (500n * KAS).toString(), kasPeriodBudget: (800n * KAS).toString(), kasPeriodSpent: "0", agentRecipientRoot: "00".repeat(32) };
  const state = { feeReserve: (5n * KAS).toString(), swapPrincipal: (1000n * KAS).toString(), paused: "0", agentRoot: buildTokenAgentTreeV6([agentPolicy]).root, swapRoot: buildSwapPolicyTreeV6([swapA]).root, policyNonce: "0" };
  const posState = { ownerIdentifier: "43".repeat(32), identifierType: 2, amount: "3000", isMinter: false };
  const noteState = { ownerIdentifier: "50".repeat(32), identifierType: 2, amount: "10000", isMinter: false };
  const chain = {
    predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 }, predecessorValue: (1005n * KAS).toString(), covenantId: "43".repeat(32),
    tokenPosition: { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: compileKcc20Program({ config, state: posState, familyBound: 2 }).p2shSpkHex, covenantId: "54".repeat(32), state: posState },
    poolNote: { outpoint: { transactionId: "08".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: compileKcc20Program({ config, state: noteState, familyBound: 2 }).p2shSpkHex, covenantId: "54".repeat(32), state: noteState },
    pool: { outpoint: { transactionId: "09".repeat(32), index: 0 }, value: (10_000n * KAS).toString(), scriptPublicKeyHex: pool0.p2shSpkHex, covenantId: "50".repeat(32), state: poolState }
  };
  const build = buildV6Transaction({ config, templateInput: template, stateInput: state, action: "tokenAtomicSell", params: { agentPk: "62".repeat(32), agents: [agentPolicy], swapPolicies: [swapA], swapPolicy: swapA, venueProfile, deadlineDaa: "10000000", amountIn: "500", minKasOut: (400n * KAS).toString() }, chain, changeXOnly: "62".repeat(32), descriptor });
  const manifest = buildSwapIntentManifest({ build, descriptor, agentPolicy });
  assert.equal(manifest.asset.trust, "ISSUER_CONTROLLED");
  assert.deepEqual(manifest.asset.issuerPowers, issuerPowers);
  assert.equal(manifest.asset.decimalsDisplay, 6);
  assert.equal(verifySwapIntentManifest({ manifest, descriptor }).verdict, "VERIFIED");
  /* omitting an issuer power, or an unknown standard, fails closed before any bytes exist */
  const { emergencyControl, ...missing } = issuerPowers;
  assert.throws(() => assets.validateAssetDescriptor({ ...descriptor, issuerPowers: missing }), /DESCRIPTOR_MALFORMED|issuerPowers/);
  assert.throws(() => assets.validateAssetDescriptor({ ...descriptor, tokenStandard: "krc20/1" }), /tokenStandard|failing closed|DESCRIPTOR/);
});
