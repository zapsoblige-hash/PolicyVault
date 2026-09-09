"use strict";
/*
 * MAINNET GENERATION-AUTHORIZATION gate (owner pre-promotion gate, 2026-09-04).
 * Fail-closed: on mainnet, ONLY the v0.4.x production generation may be
 * created/mutated. v0.5 / v0.6 / v0.7-root / v0.7-payment require explicit
 * per-generation owner authorization; UNFROZEN CANDIDATES (v0.7-kas,
 * v0.7-payment-hd) are NEVER mainnet-creatable. Testnet allows all
 * operational generations (so human testnet acceptance can exercise them).
 *
 * This gate is the remediation for the Wave-2 exposure finding: the HD
 * candidate (and every other Wave-2 generation) was reachable for mainnet
 * creation/mutation because assertOperationalNetwork only checks the
 * dual-flag, not the generation.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { assertGenerationMainnetCreatable, MAINNET_CREATABLE_GENERATIONS } = require("../src/config");

const MAINNET = { networkId: "mainnet", allowMainnet: true };
const TESTNET = { networkId: "testnet-10" };
const ALL = ["policyvault-0.4", "policyvault-0.4.1", "policyvault-0.5", "policyvault-0.6", "policyvault-0.7-root", "policyvault-0.7-payment", "policyvault-0.7-kas", "policyvault-0.7-payment-hd"];
/* F-02 (rc11 internal review): policyvault-0.4 is NOT newly creatable on
 * mainnet (18 static sig-ops => every spend is non-standard on default relay);
 * only the v0.4.1 standardness redesign is the authorized production KAS
 * generation. Historical v0.4 READ / transition compatibility stays. */
const AUTHORIZED = new Set(["policyvault-0.4.1"]);

test("mainnet: only the v0.4.1 production generation is creatable; everything else (incl. v0.4) fails closed", () => {
  for (const v of ALL) {
    if (AUTHORIZED.has(v)) {
      assert.equal(assertGenerationMainnetCreatable(MAINNET, v), v, `${v} must be mainnet-creatable (the live generation)`);
    } else {
      let threw = null;
      try { assertGenerationMainnetCreatable(MAINNET, v); } catch (e) { threw = e; }
      assert.ok(threw, `${v} must be REFUSED on mainnet`);
      assert.equal(threw.code, "GENERATION_NOT_MAINNET_AUTHORIZED", `${v} must fail closed with GENERATION_NOT_MAINNET_AUTHORIZED`);
    }
  }
});

test("the two unfrozen candidates are never mainnet-creatable (hard rule)", () => {
  for (const v of ["policyvault-0.7-kas", "policyvault-0.7-payment-hd"]) {
    assert.throws(() => assertGenerationMainnetCreatable(MAINNET, v), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
    assert.ok(!MAINNET_CREATABLE_GENERATIONS.has(v), `${v} must not be in the mainnet allowlist`);
  }
});

test("testnet allows every operational generation (human acceptance can exercise them)", () => {
  for (const v of ALL) {
    assert.equal(assertGenerationMainnetCreatable(TESTNET, v), v, `${v} must be allowed on testnet`);
  }
});

test("WIRING: every wallet-requests module enforces the gate at its create/build/submit entries", () => {
  const modules = {
    "wallet-requests-v5.js": "CONTRACT_VERSION_V5",
    "wallet-requests-v6.js": "CONTRACT_VERSION_V6",
    "wallet-requests-v7.js": "CONTRACT_VERSION_V7",
    "wallet-requests-v7-hd.js": "CONTRACT_VERSION_V7_HD"
  };
  for (const [file, ver] of Object.entries(modules)) {
    const src = fs.readFileSync(path.join(__dirname, "..", "src", file), "utf8");
    assert.ok(src.includes("assertGenerationMainnetCreatable"), `${file} must import/call the gate`);
    assert.ok(src.includes(`assertGenerationMainnetCreatable(config, ${ver})`), `${file} must gate with ${ver}`);
    // every operational-network assertion must be paired with the generation gate
    const opCount = (src.match(/assertOperationalNetwork\(config\);/g) || []).length;
    const genCount = (src.match(/assertGenerationMainnetCreatable\(config,/g) || []).length;
    assert.ok(genCount >= opCount, `${file}: every assertOperationalNetwork (${opCount}) must be paired with the generation gate (${genCount})`);
  }
});


/* ---- F-02: the v4 CREATE builder itself is gated per generation (SDK level), compat preserved ---- */
const os = require("node:os");

test("F-02 SDK: buildCreateWalletRequestV4 refuses policyvault-0.4 on mainnet with GENERATION_NOT_MAINNET_AUTHORIZED, still builds v0.4.1 (control), and builds v0.4 on testnet", async () => {
  const { loadConfig } = require("../src/config");
  const wr4 = require("../src/wallet-requests-v4");
  const { ENCODER_PATH } = require("../src/vault-builders-v4");
  const cfgT = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-f02-")) });
  if (!fs.existsSync(cfgT.silvercPath) || !fs.existsSync(ENCODER_PATH)) return; // REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder
  const saved = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  let cfgM;
  try {
    cfgM = loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-f02-m-")) });
  } finally {
    if (saved === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = saved;
  }
  const kaspa = require(cfgT.rustyKaspaModule);
  const owner = new kaspa.PrivateKey("21".repeat(32));
  const xo = owner.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const args = (config, contractVersion) => ({
    config, contractVersion, label: "f02",
    templateInput: { owner: xo, vaultId: "0f".repeat(32) }, initialAgents: [],
    initialState: { protectedValue: "1000000000", feeReserve: "100000000", approvers: [], approvalM: "0" },
    signerAddress: owner.toPublicKey().toAddress(config.networkId).toString(),
    funding: [{ outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: "500000000000", scriptPublicKeyHex: `20${xo}ac` }]
  });
  await assert.rejects(() => Promise.resolve(wr4.buildCreateWalletRequestV4(args(cfgM, "policyvault-0.4"))), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  const okM = await Promise.resolve(wr4.buildCreateWalletRequestV4(args(cfgM, "policyvault-0.4.1")));
  assert.equal(okM.contractVersion, "policyvault-0.4.1");
  assert.equal(okM.state, "BUILT");
  const okT = await Promise.resolve(wr4.buildCreateWalletRequestV4(args(cfgT, "policyvault-0.4")));
  assert.equal(okT.contractVersion, "policyvault-0.4", "testnet development behavior for v0.4 remains available");
});

test("F-02 compat: the v0.4 ABI still resolves for historical read/reconcile (only NEW mainnet creation is gated)", () => {
  const { resolveV4Abi } = require("../../core/model/vault-state-v4");
  assert.equal(resolveV4Abi("policyvault-0.4").contractRelPath, "contracts/PolicyVault.v0.4.sil");
  assert.ok(MAINNET_CREATABLE_GENERATIONS.has("policyvault-0.4.1"));
  assert.ok(!MAINNET_CREATABLE_GENERATIONS.has("policyvault-0.4"));
});
