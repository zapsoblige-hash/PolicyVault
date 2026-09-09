"use strict";

/*
 * SDK — Wave 2 Track D gate I3: THE HOSTILE MATRIX AT THE CORE BOUNDARY for
 * hierarchical delegation (docs/postlaunch/hierarchical-delegation-design-
 * freeze.md §4 implementation contract).
 *
 * PART 1 (below) exercises the three core-boundary guards the shared-core
 * PURE MODEL implements, at the pure-function level, with NO silverc/engine
 * dependency:
 *
 *   1. every HD leaf field class is refused when a proposed CHILD leaf
 *      would be broader than its parent (verifyChildNeverExceedsParent) —
 *      BEFORE anyone signs;
 *   2. a delegation op that changes anything but `childRoot` is refused
 *      (verifyDelegationOnlyChangesChildRoot) — BEFORE anyone signs;
 *   3. a spend whose amount/fee/carry falls outside the chain's
 *      effectiveAuthority (the intersection over every ancestor) is
 *      refused (verifySpendWithinEffectiveAuthority) — BEFORE anyone signs.
 *
 * PART 2 (gate I2 now built: sdk/src/vault-builders-v7-hd.js +
 * core/intent/org-root-manifest-v7-hd.js) extends coverage to the MANIFEST
 * FIELD CLASSES on REAL SDK-built manifests: chain tampering, intersection
 * (effective-authority) mismatch, per-level counter tampering, a delegation
 * op forging anything but childRoot, and expiry inversion — each is a
 * post-build mutation of an otherwise-VERIFIED
 * `policyvault-rooted-hd-vault-manifest/1` manifest that MUST be REFUSED by
 * `verifyRootedHdVaultManifestV7`, with the failing check named. Classified
 * REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) when silverc /
 * pv_call_encoder are absent — narrower in scope than the full v0.7
 * org-root I3c suite (sdk/test/org-root-hostile-matrix-v7.test.js), which
 * additionally cross-checks production-byte REJECT VECTORS end to end; that
 * cross-check is gate I2's tests/vm/tests/v7_hd_sdk_integration.rs instead.
 *
 * The covenant (contracts/PolicyVault.v0.7-payment-hd.sil) is the ONLY
 * security boundary; every guard here is DEFENCE IN DEPTH — a bypass of
 * these SDK guards changes nothing about what the real engine accepts,
 * which is proven independently by tests/vm/tests/v7_hd_production.rs and
 * tests/vm/tests/v7_hd_sdk_integration.rs. TEST DATA ONLY (no real keys, no
 * network).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const hd = require("../../core/model/hd-leaf-v7");

/*
 * PART 2 setup — a REAL, PRIVATE build of pv_call_encoder for this process.
 *
 * `tests/vm/target` is a symlink into a target directory SHARED with other
 * development lanes (CLAUDE.md: "shared cargo target — never cargo clean").
 * tests/vm/tests/v7_hd_sdk_integration.rs found (gate I2) that cargo's
 * fingerprint cache under that shared target can report `pv_call_encoder`
 * up to date (no recompilation at all) while the on-disk binary belongs to
 * a DIFFERENT worktree's source and lacks this candidate's
 * `policyvault-0.7-payment-hd` arm — 8/8 retries against the shared path
 * failed even immediately after `touch`ing the source. A PRIVATE
 * `--target-dir` sidesteps that shared fingerprint cache entirely (still
 * reuses the shared dependency/registry cache, so only this one crate's
 * objects rebuild) and is pointed at via
 * `POLICYVAULT_PV_CALL_ENCODER_PATH` (sdk/src/vault-builders-v4.js's
 * additive escape hatch) — set BEFORE any require of sdk/src/vault-builders-v4
 * (directly or transitively), since ENCODER_PATH there is a module-load-time
 * constant.
 */
const REPO_ROOT = path.join(__dirname, "..", "..");
const SILVERC_PATH = path.join(process.env.HOME || "", ".cargo", "bin", "silverc");
const TESTS_VM_DIR = path.join(REPO_ROOT, "tests", "vm");
let PART2_AVAILABLE = false;
let PART2_SKIP_REASON = "REQUIREMENT_NOT_AVAILABLE: silverc unavailable";
if (fs.existsSync(SILVERC_PATH)) {
  try {
    /* SAME private target dir tests/vm/tests/v7_hd_sdk_integration.rs uses —
     * one shared, incrementally-reused private build (~1.7GB with debug
     * symbols) instead of two, since /tmp on this host is a size-limited
     * tmpfs (ENOSPC observed once with two separate private target dirs). */
    const privateTarget = path.join(os.tmpdir(), "pv7hd-sdk-private-cargo-target");
    execFileSync("cargo", ["build", "--bin", "pv_call_encoder", "--target-dir", privateTarget], { cwd: TESTS_VM_DIR, stdio: ["ignore", "pipe", "pipe"] });
    const builtPath = path.join(privateTarget, "debug", "pv_call_encoder");
    const bytes = fs.readFileSync(builtPath);
    if (!bytes.includes(Buffer.from("policyvault-0.7-payment-hd"))) {
      PART2_SKIP_REASON = "REQUIREMENT_NOT_AVAILABLE: the privately-built pv_call_encoder lacks the policyvault-0.7-payment-hd arm";
    } else {
      process.env.POLICYVAULT_PV_CALL_ENCODER_PATH = builtPath;
      PART2_AVAILABLE = true;
    }
  } catch (e) {
    PART2_SKIP_REASON = `REQUIREMENT_NOT_AVAILABLE: private pv_call_encoder build failed: ${String(e.message).slice(0, 300)}`;
  }
}

const ZERO = "00".repeat(32);
const pk = (i) => i.toString(16).padStart(2, "0").repeat(32);

const baseLeaf = (i, extra = {}) => ({
  pk: pk(i),
  maxPerSpend: "250",
  periodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  periodSpent: "0",
  maxFeePerTx: "60000",
  maxCarryKas: "25000000",
  expiryDaa: "9000000",
  recipientRoot: ZERO,
  childRoot: ZERO,
  ...extra
});

/* ---- 1. every leaf field class: a broader child is refused ---- */

const BROADENING_FIELD_CASES = [
  ["maxPerSpend", { maxPerSpend: "251" }],
  ["periodBudget", { periodBudget: "401" }],
  ["maxFeePerTx", { maxFeePerTx: "60001" }],
  ["maxCarryKas", { maxCarryKas: "25000001" }],
  ["expiryDaa", { expiryDaa: "9000001" }]
];

test("hd-hostile: every leaf field class is refused when the child is broader than the parent", () => {
  const parent = baseLeaf(1);
  for (const [field, override] of BROADENING_FIELD_CASES) {
    const child = baseLeaf(2, override);
    const r = hd.verifyChildNeverExceedsParent(parent, child);
    assert.equal(r.ok, false, `${field} broadened by 1 must be refused`);
    assert.deepEqual(r.violations, [field], `the refusal must name exactly ${field}`);
  }
});

test("hd-hostile: an honest child (every field <= the parent) is accepted by the guard", () => {
  const parent = baseLeaf(1);
  const honestChild = baseLeaf(2, { maxPerSpend: "100", periodBudget: "100", maxFeePerTx: "1", maxCarryKas: "1", expiryDaa: "1" });
  assert.equal(hd.verifyChildNeverExceedsParent(parent, honestChild).ok, true);
});

test("hd-hostile: EVERY field simultaneously broadened is refused with every violation named", () => {
  const parent = baseLeaf(1);
  const allBroader = baseLeaf(2, { maxPerSpend: "999", periodBudget: "999", maxFeePerTx: "999999", maxCarryKas: "999999999", expiryDaa: "9500000" });
  const r = hd.verifyChildNeverExceedsParent(parent, allBroader);
  assert.equal(r.ok, false);
  assert.deepEqual(r.violations, ["maxPerSpend", "periodBudget", "maxFeePerTx", "maxCarryKas", "expiryDaa"]);
});

/* ---- 2. delegation op that changes anything but childRoot is refused ---- */

test("hd-hostile: a delegation op that ALSO changes a policy field is refused, even though childRoot legitimately moves", () => {
  const current = baseLeaf(1, { childRoot: ZERO });
  const newChildRoot = "11".repeat(32);
  const honestProposed = { ...current, childRoot: newChildRoot };
  assert.equal(hd.verifyDelegationOnlyChangesChildRoot(current, honestProposed).ok, true);

  const forgedFields = [
    ["maxPerSpend", "999"],
    ["periodBudget", "999"],
    ["periodLengthDaa", "1"],
    ["periodStartDaa", "1"],
    ["periodSpent", "1"],
    ["maxFeePerTx", "1"],
    ["maxCarryKas", "1"],
    ["expiryDaa", "1"],
    ["recipientRoot", "22".repeat(32)],
    ["pk", pk(9)]
  ];
  for (const [field, value] of forgedFields) {
    const forged = { ...current, childRoot: newChildRoot, [field]: value };
    const r = hd.verifyDelegationOnlyChangesChildRoot(current, forged);
    assert.equal(r.ok, false, `a delegation op forging ${field} must be refused`);
    assert.deepEqual(r.violations, [field]);
    assert.equal(r.childRootChanged, true);
  }
});

test("hd-hostile: a no-op delegation (childRoot unchanged) is reported honestly (not a policy violation, but childRootChanged is false)", () => {
  const current = baseLeaf(1, { childRoot: "33".repeat(32) });
  const noOp = { ...current };
  const r = hd.verifyDelegationOnlyChangesChildRoot(current, noOp);
  assert.equal(r.ok, true);
  assert.equal(r.childRootChanged, false);
});

/* ---- 3. effective-authority mismatch is refused ---- */

test("hd-hostile: a spend amount above the chain's effective (minimum-over-ancestors) cap is refused", () => {
  const a1 = baseLeaf(1, { maxPerSpend: "250", maxFeePerTx: "60000", maxCarryKas: "25000000" });
  const b = baseLeaf(2, { maxPerSpend: "9999999", maxFeePerTx: "9999999", maxCarryKas: "9999999" }); // inflated child leaf
  const chain = [{ leaf: a1 }, { leaf: b }];

  const honest = hd.verifySpendWithinEffectiveAuthority(chain, { amount: "250" });
  assert.equal(honest.ok, true);
  assert.equal(honest.effectiveAuthority.maxPerSpend, 250n, "the PARENT's tighter cap binds, never the inflated child's");

  const overCap = hd.verifySpendWithinEffectiveAuthority(chain, { amount: "251" });
  assert.equal(overCap.ok, false);
  assert.deepEqual(overCap.violations, ["maxPerSpend"]);
});

test("hd-hostile: fee and carry are independently checked against the chain's minimum", () => {
  const a1 = baseLeaf(1, { maxFeePerTx: "20000", maxCarryKas: "1000000" });
  const b = baseLeaf(2, { maxFeePerTx: "999999", maxCarryKas: "999999" });
  const chain = [{ leaf: a1 }, { leaf: b }];

  const feeOver = hd.verifySpendWithinEffectiveAuthority(chain, { feeSompi: "20001" });
  assert.deepEqual(feeOver.violations, ["maxFeePerTx"]);

  const carryOver = hd.verifySpendWithinEffectiveAuthority(chain, { carrySompi: "1000001" });
  assert.deepEqual(carryOver.violations, ["maxCarryKas"]);

  const bothOver = hd.verifySpendWithinEffectiveAuthority(chain, { feeSompi: "20001", carrySompi: "1000001" });
  assert.deepEqual(bothOver.violations, ["maxFeePerTx", "maxCarryKas"]);

  const allHonest = hd.verifySpendWithinEffectiveAuthority(chain, { amount: "1", feeSompi: "20000", carrySompi: "999999" });
  assert.equal(allHonest.ok, true);
});

test("hd-hostile: effective-authority mismatch across a full 3-level chain uses the TIGHTEST ancestor at every level, not just the immediate parent", () => {
  const a1 = baseLeaf(1, { maxPerSpend: "50" }); // the TIGHTEST — a grandparent cap
  const b = baseLeaf(2, { maxPerSpend: "200" });
  const c = baseLeaf(3, { maxPerSpend: "150" });
  const chain = [{ leaf: a1 }, { leaf: b }, { leaf: c }];
  const eff = hd.effectiveAuthority(chain);
  assert.equal(eff.maxPerSpend, 50n, "the grandparent's cap must bind even though the immediate parent's and the leaf's own are looser");
  assert.equal(hd.verifySpendWithinEffectiveAuthority(chain, { amount: "50" }).ok, true);
  assert.equal(hd.verifySpendWithinEffectiveAuthority(chain, { amount: "51" }).ok, false);
});

/* ---- recipient allowlist intersection (bonus coverage: every level, not just one) ---- */

test("hd-hostile: a recipient allowed by the child but refused by an ancestor's own recipientRoot fails at that level", () => {
  const recipientMerkle = require("../../core/model/recipient-merkle-v3");
  const honestRecipient = pk(0x65);
  const outsider = pk(0x69);

  const parentTree = recipientMerkle.buildRecipientTree([outsider]); // parent allows ONLY the outsider
  const childTree = recipientMerkle.buildRecipientTree([honestRecipient]); // child allows the honest recipient

  const a1 = baseLeaf(1, { recipientRoot: parentTree.root });
  const b = baseLeaf(2, { recipientRoot: childTree.root });
  const chain = [{ leaf: a1 }, { leaf: b }];

  const parentProof = recipientMerkle.generateRecipientProof(parentTree, outsider);
  const childProof = recipientMerkle.generateRecipientProof(childTree, honestRecipient);

  // the honest recipient satisfies the CHILD's own allowlist but not the PARENT's
  const wrongProofForParent = { siblingsHex: childProof.siblingsHex, pathBits: childProof.pathBits };
  const r = hd.verifyRecipientAllowedByEveryLevel(chain, honestRecipient, [wrongProofForParent, childProof]);
  assert.equal(r.ok, false);
  assert.equal(r.level, 1, "the refusal must be attributed to the PARENT's level, not the child's");

  // the outsider satisfies the parent but the child never allowed them
  const outsiderChildProofAttempt = { siblingsHex: childProof.siblingsHex, pathBits: childProof.pathBits };
  const r2 = hd.verifyRecipientAllowedByEveryLevel(chain, outsider, [parentProof, outsiderChildProofAttempt]);
  assert.equal(r2.ok, false);
  assert.equal(r2.level, 2);
});

/* ==================================================================== */
/* PART 2 — the MANIFEST FIELD CLASSES, on REAL SDK-built manifests       */
/* ==================================================================== */

(() => {
  if (!PART2_AVAILABLE) {
    test("hd-hostile PART 2 (manifest field classes)", { skip: PART2_SKIP_REASON }, () => {});
    return;
  }

  const { loadConfig } = require("../src/config");
  const assets = require("../../core/assets");
  const { compileKcc20Program } = require("../src/token-program-kcc20");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { deriveRootPinsV7, assertRootPinsMatchV7 } = require("../src/contract-compiler-v7");
  const { buildHdSpendTransaction, buildHdDelegationTransaction } = require("../src/vault-builders-v7-hd");
  const { buildRootedHdVaultManifestV7, verifyRootedHdVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7-hd");
  const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");

  const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7hd-hostile-")) });
  const kaspa = require(config.rustyKaspaModule);
  const KAS = 100000000n;
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const l1Key = KEY(0x62);
  const l2Key = KEY(0x63);
  const recipientKey = KEY(0x65);
  const fuelKey = KEY(0x66);
  const recoveryKey = KEY(0x51);
  const successorKey = KEY(0x7f);
  const ownerKeys = [KEY(0x71), KEY(0x72), KEY(0x73)];
  function slots(keys) {
    const out = [];
    for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? XO(keys[i]) : INACTIVE_SLOT_KEY);
    return out;
  }
  const ORG_ID = pk(0xa7);
  const ROOT_ID = pk(0x52);
  const VAULT_COV_ID = pk(0x43);
  const TOKEN_FAMILY = pk(0x54);
  const VAULT_ID = pk(0x44);
  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: XO(successorKey), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
  const ownerSet3 = { owners: slots(ownerKeys), ownerM: 2, emergencyK: 1, recoveryM: 2 };
  const refProgram = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: pk(0x11),
    displayName: "HD Hostile-Matrix Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 8,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet: ownerSet3, covenantId: ROOT_ID });
  const vaultTemplate = { vaultId: VAULT_ID, descriptorHash: assets.computeDescriptorHash(descriptor), tokenCovenantId: TOKEN_FAMILY, templateVmHash: refProgram.templateVmHashBlake2b256, templatePrefixLen: refProgram.geometry.prefixLen, templateStateLen: refProgram.geometry.stateLen, templateSuffixLen: refProgram.geometry.suffixLen, ...rootPins, recoveryPk: XO(recoveryKey) };
  assertRootPinsMatchV7({ config, vaultTemplate, rootTemplate, rootOwnerSet: ownerSet3 });

  const leaf = (ownerKey, extra = {}) => ({ pk: XO(ownerKey), maxPerSpend: "250", periodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", periodSpent: "0", maxFeePerTx: "60000", maxCarryKas: (KAS / 4n).toString(), expiryDaa: "9000000", recipientRoot: buildRecipientTree([XO(recipientKey)]).root, childRoot: ZERO, ...extra });
  const l2Kid = { leaf: leaf(l2Key), kids: [] };
  const l1n0 = { leaf: leaf(l1Key), kids: [l2Kid] };
  const l1n1 = { leaf: leaf(l1Key), kids: [] };
  const tree = [l1n0, l1n1];
  const agentRoot0 = hd.forestRoot(tree);
  const vaultState = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: agentRoot0, policyNonce: "0", ...over });
  const vaultChain = (over = {}) => ({ predecessorOutpoint: { transactionId: pk(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), fuel: { outpoint: { transactionId: pk(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }, ...over });
  function tokenPositionFor(amount) {
    const st = { ownerIdentifier: VAULT_COV_ID, identifierType: 2, amount: String(amount), isMinter: false };
    const program = compileKcc20Program({ config, state: st, familyBound: 2 });
    return { outpoint: { transactionId: pk(0x02), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
  }

  function honestSpendManifest() {
    const build = buildHdSpendTransaction({
      config,
      templateInput: vaultTemplate,
      stateInput: vaultState(),
      action: "hdSpend",
      params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: "100", recipientCarryKasSompi: (KAS / 10n).toString(), recipientListsByLevel: [[XO(recipientKey)]] },
      chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }),
      changeXOnly: XO(fuelKey),
      descriptor
    });
    return buildRootedHdVaultManifestV7({ build, descriptor });
  }
  function honestDelegationManifest() {
    const build = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "delegateSetChildRoot1", params: { tree, path: [1], newChildRoot: "aa".repeat(32) }, chain: vaultChain(), changeXOnly: XO(fuelKey) });
    return buildRootedHdVaultManifestV7({ build });
  }

  test("hd-hostile manifest: an honest spend and an honest delegation manifest both VERIFY", () => {
    assert.equal(verifyRootedHdVaultManifestV7({ manifest: honestSpendManifest() }).verdict, "VERIFIED");
    assert.equal(verifyRootedHdVaultManifestV7({ manifest: honestDelegationManifest() }).verdict, "VERIFIED");
  });

  test("hd-hostile manifest: CHAIN TAMPERING — any single field of any ancestor leaf is refused (fold breaks)", () => {
    const fields = [
      ["maxPerSpend", "999999"],
      ["periodBudget", "999999"],
      ["maxFeePerTx", "999999"],
      ["maxCarryKas", "999999999"],
      ["pk", pk(0x99)],
      ["recipientRoot", "cd".repeat(32)]
    ];
    for (const [field, value] of fields) {
      const m = JSON.parse(JSON.stringify(honestSpendManifest()));
      m.ancestorChain[0].leaf[field] = value;
      const r = verifyRootedHdVaultManifestV7({ manifest: m });
      assert.equal(r.verdict, "REFUSED", `tampering ${field} must be refused`);
      assert.ok(r.failures.some((f) => f.name === "ancestorChainFoldsToStateBefore"), `${field}: the fold check must name the tamper`);
    }
  });

  test("hd-hostile manifest: INTERSECTION MISMATCH — a declared effectiveAuthority looser than the true ancestor minimum is refused", () => {
    const m = JSON.parse(JSON.stringify(honestSpendManifest()));
    m.effectiveAuthority.maxPerSpend = "999999";
    const r = verifyRootedHdVaultManifestV7({ manifest: m });
    assert.equal(r.verdict, "REFUSED");
    assert.ok(r.failures.some((f) => f.name === "effectiveAuthorityMatchesDeclared"));
  });

  test("hd-hostile manifest: COUNTERS — a tampered successor agentRoot (wrong nested refold) is refused", () => {
    const m = JSON.parse(JSON.stringify(honestSpendManifest()));
    m.stateAfter.state.agentRoot = "ee".repeat(32);
    const r = verifyRootedHdVaultManifestV7({ manifest: m });
    assert.equal(r.verdict, "REFUSED");
    assert.ok(r.failures.some((f) => f.name === "successorAgentRootIsCorrectSpendRefold"));
  });

  test("hd-hostile manifest: DELEGATION CHANGING ANYTHING BUT childRoot — a forged non-childRoot field on the delegating parent is refused", () => {
    const fields = ["maxPerSpend", "periodBudget", "maxFeePerTx", "maxCarryKas", "expiryDaa", "pk", "recipientRoot"];
    for (const field of fields) {
      const m = JSON.parse(JSON.stringify(honestDelegationManifest()));
      m.ancestorChain[0].leaf[field] = field === "pk" || field === "recipientRoot" ? "ab".repeat(32) : "999999";
      const r = verifyRootedHdVaultManifestV7({ manifest: m });
      assert.equal(r.verdict, "REFUSED", `forging ${field} on the delegating parent must be refused`);
      /* the fold breaks (the declared chain no longer reproduces stateBefore) */
      assert.ok(r.failures.some((f) => f.name === "ancestorChainFoldsToStateBefore"), `${field}: the fold check must name the tamper`);
    }
  });

  test("hd-hostile manifest: EXPIRY INVERSION — a child expiryDaa greater than its parent's is refused (verifyExpiryMonotone)", () => {
    /* build a genuinely 2-level chain so there is a real parent/child pair */
    const build = buildHdSpendTransaction({
      config,
      templateInput: vaultTemplate,
      stateInput: vaultState(),
      action: "childSpendL2",
      params: { tree, path: [0, 0], recipient: XO(recipientKey), spendAmount: "50", recipientCarryKasSompi: (KAS / 10n).toString(), recipientListsByLevel: [[XO(recipientKey)], [XO(recipientKey)]] },
      chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }),
      changeXOnly: XO(fuelKey),
      descriptor
    });
    const manifest = buildRootedHdVaultManifestV7({ build, descriptor });
    assert.equal(verifyRootedHdVaultManifestV7({ manifest }).verdict, "VERIFIED", "sanity: the honest 2-level chain verifies first");

    const m = JSON.parse(JSON.stringify(manifest));
    /* level 2 (the child) is inflated past level 1 (the parent)'s expiryDaa */
    m.ancestorChain[1].leaf.expiryDaa = (BigInt(m.ancestorChain[0].leaf.expiryDaa) + 1n).toString();
    const r = verifyRootedHdVaultManifestV7({ manifest: m });
    assert.equal(r.verdict, "REFUSED");
    /* the fold ALSO breaks (expiryDaa is part of the leaf hash), so both the
     * generic tamper detector and the semantic expiry-monotonicity check
     * independently catch this row — DEFENCE IN DEPTH, exactly as intended */
    assert.ok(r.failures.some((f) => f.name === "ancestorChainFoldsToStateBefore" || f.name === "expiryMonotoneDescending"), "either independent check must name the inversion");
  });

  test("hd-hostile manifest: manifestHash tamper-evidence — any field edit invalidates the recomputed hash", () => {
    const m = JSON.parse(JSON.stringify(honestSpendManifest()));
    m.accounting.token.spendAmount = "999";
    const r = verifyRootedHdVaultManifestV7({ manifest: m });
    assert.equal(r.verdict, "REFUSED");
    assert.ok(r.failures.some((f) => f.name === "manifestHash"));
  });
})();
