"use strict";
/*
 * MAINNET GENERATION-AUTHORIZATION gate (owner pre-promotion gate, 2026-09-04;
 * REPLACED by the owner-reviewed set of the v0.7 MAINNET ENABLEMENT directive,
 * 2026-09-10). Fail-closed on mainnet:
 *
 *   CREATABLE  policyvault-0.4.1 (frozen KAS safe-payment vault), policyvault-0.7-root
 *              (frozen organizational root), policyvault-0.7-kas (rooted KAS safe-payment
 *              vault — CANDIDATE until the owner's conditional byte freeze is satisfied;
 *              the proposed mainnet set the candidate release carries for review).
 *   OPERABLE   every generation that has EVER been mainnet-creatable: mutation /
 *              submission / reconciliation of EXISTING mainnet state (rollback of
 *              creation never strands state).
 *   KILL SWITCH POLICYVAULT_MAINNET_CREATION_DISABLED removes creatable generations at
 *              runtime (existing state stays operable); unknown names refuse to start.
 *
 * v0.4 (non-standard on default relay, F-02), v0.5 / v0.6 (token controllers),
 * v0.7-payment (the rooted TOKEN profile) and the v0.7-payment-hd candidate are in
 * NEITHER set. Testnet allows every operational generation (human acceptance).
 * The set is a list of exact strings — never a family prefix.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("node:os");
const {
  loadConfig,
  assertGenerationMainnetCreatable,
  assertGenerationMainnetOperable,
  isGenerationMainnetCreatable,
  parseMainnetCreationDisabled,
  MAINNET_CREATABLE_GENERATIONS,
  MAINNET_OPERABLE_GENERATIONS
} = require("../src/config");

const MAINNET = { networkId: "mainnet", allowMainnet: true };
const TESTNET = { networkId: "testnet-10" };
const ALL = ["policyvault-0.4", "policyvault-0.4.1", "policyvault-0.5", "policyvault-0.6", "policyvault-0.7-root", "policyvault-0.7-payment", "policyvault-0.7-kas", "policyvault-0.7-payment-hd"];
const REVIEWED_SET = ["policyvault-0.4.1", "policyvault-0.7-root", "policyvault-0.7-kas"];
const AUTHORIZED = new Set(REVIEWED_SET);
const NEVER = ["policyvault-0.4", "policyvault-0.5", "policyvault-0.6", "policyvault-0.7-payment", "policyvault-0.7-payment-hd"];

test("mainnet: EXACTLY the owner-reviewed set (v0.4.1, v0.7-root, v0.7-kas) is creatable; everything else (incl. v0.4, the token profiles and the HD candidate) fails closed with GENERATION_NOT_MAINNET_AUTHORIZED", () => {
  assert.deepEqual([...MAINNET_CREATABLE_GENERATIONS].sort(), [...REVIEWED_SET].sort(), "the creatable set is exactly the reviewed list of exact strings");
  for (const v of ALL) {
    if (AUTHORIZED.has(v)) {
      assert.equal(assertGenerationMainnetCreatable(MAINNET, v), v, `${v} must be mainnet-creatable (reviewed set)`);
    } else {
      let threw = null;
      try { assertGenerationMainnetCreatable(MAINNET, v); } catch (e) { threw = e; }
      assert.ok(threw, `${v} must be REFUSED on mainnet`);
      assert.equal(threw.code, "GENERATION_NOT_MAINNET_AUTHORIZED", `${v} must fail closed with GENERATION_NOT_MAINNET_AUTHORIZED`);
      assert.ok(threw.message.includes(`mainnet: covenant generation "${v}" is NOT owner-authorized for mainnet creation/mutation — refusing (fail closed).`), "the refusal sentence the browser explain layer recognizes is preserved");
    }
  }
  for (const prefix of ["policyvault-0.7", "policyvault-0.7-", "v0.7-*", "policyvault-0.7-kas-next"]) {
    assert.throws(() => assertGenerationMainnetCreatable(MAINNET, prefix), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED", `${prefix}: never a family prefix, never a near-miss`);
  }
});

test("the HD candidate and the rooted TOKEN profile are never mainnet-creatable or mainnet-operable; the KAS candidate is in the reviewed set (directive 2026-09-10) and is labelled candidate elsewhere, not here", () => {
  for (const v of NEVER) {
    assert.throws(() => assertGenerationMainnetCreatable(MAINNET, v), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
    assert.throws(() => assertGenerationMainnetOperable(MAINNET, v), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED", `${v} has never been creatable, so it has no mainnet state to operate`);
    assert.ok(!MAINNET_CREATABLE_GENERATIONS.has(v) && !MAINNET_OPERABLE_GENERATIONS.has(v), `${v} is in neither set`);
  }
  assert.ok(MAINNET_CREATABLE_GENERATIONS.has("policyvault-0.7-kas"));
});

test("OPERABLE ⊇ CREATABLE, and every operable generation was once creatable (today the sets are equal): mutation/submission/reconciliation of existing mainnet state is gated on the operable set", () => {
  for (const v of MAINNET_CREATABLE_GENERATIONS) assert.ok(MAINNET_OPERABLE_GENERATIONS.has(v), `${v} creatable => operable`);
  assert.deepEqual([...MAINNET_OPERABLE_GENERATIONS].sort(), [...MAINNET_CREATABLE_GENERATIONS].sort());
  for (const v of REVIEWED_SET) assert.equal(assertGenerationMainnetOperable(MAINNET, v), v);
});

test("KILL SWITCH: creation of a listed generation is refused (distinct sentence, same closed code) while its existing state stays operable; the other creatable generations are untouched; unknown or non-creatable names refuse to start", () => {
  const disabled = { networkId: "mainnet", allowMainnet: true, mainnetCreationDisabled: parseMainnetCreationDisabled("policyvault-0.7-kas") };
  let threw = null;
  try { assertGenerationMainnetCreatable(disabled, "policyvault-0.7-kas"); } catch (e) { threw = e; }
  assert.ok(threw && threw.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  assert.ok(threw.message.includes('mainnet: creation of covenant generation "policyvault-0.7-kas" is DISABLED by operator configuration (POLICYVAULT_MAINNET_CREATION_DISABLED) — refusing this new genesis (fail closed).'));
  assert.equal(assertGenerationMainnetOperable(disabled, "policyvault-0.7-kas"), "policyvault-0.7-kas", "existing KAS vaults stay manageable");
  assert.equal(assertGenerationMainnetCreatable(disabled, "policyvault-0.7-root"), "policyvault-0.7-root");
  assert.equal(assertGenerationMainnetCreatable(disabled, "policyvault-0.4.1"), "policyvault-0.4.1");
  assert.equal(isGenerationMainnetCreatable(disabled, "policyvault-0.7-kas"), false);
  assert.equal(isGenerationMainnetCreatable(disabled, "policyvault-0.7-root"), true);
  assert.equal(isGenerationMainnetCreatable(MAINNET, "policyvault-0.7-kas"), true);
  /* the switch can only REMOVE: it never adds a generation */
  const all = { ...MAINNET, mainnetCreationDisabled: parseMainnetCreationDisabled("policyvault-0.4.1, policyvault-0.7-root ,policyvault-0.7-kas") };
  for (const v of REVIEWED_SET) assert.throws(() => assertGenerationMainnetCreatable(all, v), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  for (const v of REVIEWED_SET) assert.equal(assertGenerationMainnetOperable(all, v), v);
  for (const bad of ["policyvault-0.7-payment", "policyvault-0.7-*", "v0.7-kas", "policyvault-0.7-payment-hd", "nonsense"]) {
    assert.throws(() => parseMainnetCreationDisabled(bad), /not a mainnet-creatable generation/, `${bad}: unknown / non-creatable names refuse to start`);
  }
  assert.deepEqual([...parseMainnetCreationDisabled(undefined)], []);
  assert.deepEqual([...parseMainnetCreationDisabled("")], []);
  /* the switch does not apply on testnet (creation there is a development/acceptance matter) */
  assert.equal(assertGenerationMainnetCreatable({ networkId: "testnet-10", mainnetCreationDisabled: parseMainnetCreationDisabled("policyvault-0.7-kas") }, "policyvault-0.7-kas"), "policyvault-0.7-kas");
});

test("KILL SWITCH through loadConfig: POLICYVAULT_MAINNET_CREATION_DISABLED is parsed at load (fail closed on a bad value) and carried on the frozen config", () => {
  const saved = process.env.POLICYVAULT_MAINNET_CREATION_DISABLED;
  try {
    process.env.POLICYVAULT_MAINNET_CREATION_DISABLED = "policyvault-0.7-kas,policyvault-0.7-root";
    const cfg = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ks-")) });
    assert.deepEqual([...cfg.mainnetCreationDisabled].sort(), ["policyvault-0.7-kas", "policyvault-0.7-root"]);
    process.env.POLICYVAULT_MAINNET_CREATION_DISABLED = "policyvault-0.7-payment-hd";
    assert.throws(() => loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ks-")) }), /not a mainnet-creatable generation/);
    process.env.POLICYVAULT_MAINNET_CREATION_DISABLED = "policyvault-0.7-kas;policyvault-0.7-root";
    assert.throws(() => loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ks-")) }), /not a mainnet-creatable generation/, "a wrong separator is a typo, never silently ignored");
    delete process.env.POLICYVAULT_MAINNET_CREATION_DISABLED;
    const clean = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ks-")) });
    assert.deepEqual([...clean.mainnetCreationDisabled], []);
    assert.deepEqual([...loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ks-")), mainnetCreationDisabled: ["policyvault-0.4.1"] }).mainnetCreationDisabled], ["policyvault-0.4.1"], "an override array is accepted too");
  } finally {
    if (saved === undefined) delete process.env.POLICYVAULT_MAINNET_CREATION_DISABLED; else process.env.POLICYVAULT_MAINNET_CREATION_DISABLED = saved;
  }
});

test("KILL SWITCH re-load is idempotent: loadConfig(existingConfig) accepts the already-parsed Set (the PG suites' reopen pattern) and keeps exactly the same generations", () => {
  const first = mainnetConfig({ mainnetCreationDisabled: ["policyvault-0.7-kas"] });
  const again = mainnetConfig({ ...first, mainnetCreationDisabled: first.mainnetCreationDisabled });
  assert.deepEqual([...again.mainnetCreationDisabled], ["policyvault-0.7-kas"]);
  assert.throws(() => mainnetConfig({ mainnetCreationDisabled: new Set(["policyvault-0.7-kaz"]) }), /refusing to start/);
});

test("testnet allows every operational generation (human acceptance can exercise them)", () => {
  for (const v of ALL) {
    assert.equal(assertGenerationMainnetCreatable(TESTNET, v), v, `${v} must be allowed on testnet`);
    assert.equal(assertGenerationMainnetOperable(TESTNET, v), v);
  }
});

test("WIRING: every wallet-requests module enforces a generation gate at its create/build/submit entries — creation entries the CREATABLE gate, mutation entries the OPERABLE gate", () => {
  const modules = {
    "wallet-requests-v5.js": ["assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V5)"],
    "wallet-requests-v6.js": ["assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V6)"],
    "wallet-requests-v7.js": ["assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_ROOT)", "assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7)", "assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7_ROOT)", "assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7)", "assertGenerationMainnetOperable(config, kasProfile.CONTRACT_VERSION_V7_KAS)", "assertGenerationMainnetOperable(config, op.profile ?? CONTRACT_VERSION_V7)"],
    "wallet-requests-v7-hd.js": ["assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_HD)"],
    "wallet-requests-v7-kas.js": ["assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_KAS)", "assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7_KAS)"]
  };
  for (const [file, needles] of Object.entries(modules)) {
    const src = fs.readFileSync(path.join(__dirname, "..", "src", file), "utf8");
    for (const needle of needles) assert.ok(src.includes(needle), `${file} must gate with ${needle}`);
    // every operational-network assertion must be paired with a generation gate (creatable or operable)
    const opCount = (src.match(/assertOperationalNetwork\(config\);/g) || []).length;
    const genCount = (src.match(/assertGenerationMainnet(Creatable|Operable)\(config,/g) || []).length;
    assert.ok(genCount >= opCount, `${file}: every assertOperationalNetwork (${opCount}) must be paired with a generation gate (${genCount})`);
  }
  /* the KAS module's genesis entry is a CREATION entry: assertGate(..., "create") is used exactly at genesis build + genesis submit */
  const kas = fs.readFileSync(path.join(__dirname, "..", "src", "wallet-requests-v7-kas.js"), "utf8");
  assert.equal((kas.match(/assertGate\(config, "[A-Z_]+", "create"\)/g) || []).length, 2, "genesis build + genesis submit are the two creation entries");
});

/* ---- DIRECT ENTRY POINTS on a MAINNET-configured store (no node, no root): a creation gate refuses BEFORE any durable record ---- */
function mainnetConfig(over = {}) {
  const saved = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  try {
    return loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-gate-m-")), ...over });
  } finally {
    if (saved === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = saved;
  }
}
test("DIRECT ENTRY POINTS (mainnet config): KAS genesis under the kill switch, the HD genesis, and the rooted TOKEN genesis are refused with GENERATION_NOT_MAINNET_AUTHORIZED before any durable write; a root genesis under the kill switch likewise", async () => {
  const wr7 = require("../src/wallet-requests-v7");
  const wr7hd = require("../src/wallet-requests-v7-hd");
  const wr7kas = require("../src/wallet-requests-v7-kas");
  const { getStore, Categories } = require("../src/store");
  const cfg = mainnetConfig({ mainnetCreationDisabled: ["policyvault-0.7-kas", "policyvault-0.7-root"] });
  const rootId = "ab".repeat(32);
  const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
  const dummy = { config: cfg, rootCovenantId: rootId, label: "x", recoveryAddress: "kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn", signerAddress: "kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn", funding: [{ outpoint: { transactionId: H(1), index: 0 }, amount: "100000000000", scriptPublicKeyHex: `20${H(2)}ac` }] };
  await assert.rejects(() => wr7kas.buildKasVaultGenesisRequest({ ...dummy, agents: [], depositKas: "1", feeReserveKas: "1" }), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED" && /DISABLED by operator configuration/.test(e.message));
  await assert.rejects(() => wr7hd.buildHdVaultGenesisRequest({ ...dummy, descriptor: {}, initialAgents: [], feeReserveKas: "1" }), (e) => e.code === "BUILD_FAILED" && /policyvault-0.7-payment-hd" is NOT owner-authorized/.test(e.message));
  await assert.rejects(() => wr7.buildRootedVaultGenesisRequest({ ...dummy, descriptor: {}, agents: [], depositKas: "0", feeReserveKas: "1" }), (e) => e.code === "BUILD_FAILED" && /policyvault-0.7-payment" is NOT owner-authorized/.test(e.message));
  await assert.rejects(() => wr7.buildRootGenesisRequest({ config: cfg, label: "x", owners: [{ slot: 1, publicKey: H(3) }], ownerM: 1, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: dummy.signerAddress, funding: dummy.funding }), (e) => e.code === "BUILD_FAILED" && /policyvault-0.7-root" is DISABLED by operator configuration/.test(e.message));
  assert.equal((await getStore(cfg).listValues(Categories.REQUEST, { strict: true })).length, 0, "no durable request was written by any refused creation");
  assert.equal((await getStore(cfg).listValues(Categories.ORG_ROOT_REQUEST, { strict: true })).length, 0);
});

/* ---- F-02: the v4 CREATE builder itself is gated per generation (SDK level), compat preserved ---- */

test("F-02 SDK: buildCreateWalletRequestV4 refuses policyvault-0.4 on mainnet with GENERATION_NOT_MAINNET_AUTHORIZED, still builds v0.4.1 (control), and builds v0.4 on testnet", async () => {
  const wr4 = require("../src/wallet-requests-v4");
  const { ENCODER_PATH } = require("../src/vault-builders-v4");
  const cfgT = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-f02-")) });
  if (!fs.existsSync(cfgT.silvercPath) || !fs.existsSync(ENCODER_PATH)) return; // REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder
  const cfgM = mainnetConfig();
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
