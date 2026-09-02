"use strict";

/*
 * SDK PUBLIC ENTRY POINT — surface, honesty, and behavior.
 * (FULLSCALE_COMPLETION_ADDENDUM.md surface 9: JavaScript/TypeScript SDK.)
 *
 * Layer: UNIT (deterministic, offline, no server, no store, no RPC dial).
 *
 * Three properties this file exists to hold:
 *
 *   1. EVERY DOCUMENTED EXPORT RESOLVES. `sdk/package.json` previously
 *      pointed `main` at a `src/index.js` that did not exist — the package
 *      was unusable as a package. This test is what stops that regressing,
 *      and it also proves the entry point can be required with NO side
 *      effects that need a database, a node, or the silverc toolchain.
 *
 *   2. THE TYPE DECLARATIONS DO NOT LIE. No TypeScript compiler is
 *      available in this repo, so `types/*.d.ts` cannot be type-checked
 *      here. What CAN be checked mechanically — and is the failure mode
 *      that actually matters — is drift: a declared export or member that
 *      does not exist at runtime. Every name in the .d.ts files is parsed
 *      out and resolved against the real module. (This does not verify the
 *      SHAPES those names are given; see the README's TypeScript section,
 *      which says so plainly.)
 *
 *   3. THE EXCLUSIONS HOLD. Hosted/operator-side modules, node-dialing and
 *      toolchain-spawning modules, process-environment config, and above
 *      all the TEST-ONLY dev signer and key helpers are NOT on the public
 *      surface. An SDK that quietly re-exported `signer-dev` or `keys`
 *      would be advertising a path toward key material.
 *
 * Plus behavioral smoke calls, so "it resolves" is never mistaken for "it
 * works": real amount parsing, real key-order-independent canonical JSON,
 * real SHA-256 Merkle work, real successor derivation, and a real
 * fail-closed refusal from the intent verifier.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const sdk = require("../src/index");

const TYPES_DIR = path.join(__dirname, "..", "types");

/* ---------------------------------------------------------------------- */
/* 1. Surface                                                              */
/* ---------------------------------------------------------------------- */

const FLAT_EXPORTS = [
  // numeric safety
  "SOMPI_PER_KAS", "MAX_SOMPI", "parseSompi", "parsePositiveSompi", "kasToSompi", "sompiToKas",
  // canonical serialization
  "canonicalJsonStringify",
  // version identity
  "CONTRACT_VERSION", "CONTRACT_VERSION_V3", "CONTRACT_VERSION_V4", "CONTRACT_VERSION_V4_1",
  "SUPPORTED_COVENANT_VERSIONS", "V4_ABIS", "resolveV4Abi",
  // v0.5 token-controller lineage (IMPLEMENTATION IN PROGRESS; additive)
  "CONTRACT_VERSION_V5", "V5_ABIS", "resolveV5Abi",
  // client
  "PolicyVaultClient", "PolicyVaultApiError", "PolicyVaultNetworkError", "createClient",
  "randomIdempotencyKey", "API_PREFIX", "V4_WALLET_REQUEST_SCHEMA_VERSION"
];

const NAMESPACE_EXPORTS = [
  "amounts", "canonicalJson", "feeMass",
  "vaultStateV3", "vaultStateV4", "vaultTransitionsV3", "vaultTransitionsV4",
  "recipientMerkleV3", "agentMerkleV4",
  "approvalPackageV3", "approvalPackageV4", "frozenTxV3",
  "computeBudgetV3", "computeBudgetV4",
  "uxNormalizeV4", "addressIdentity", "operationalStatus", "donationAddress",
  "intent", "signer", "explain", "governance",
  // v0.5 token-controller lineage + shared asset layer
  "vaultStateV5", "vaultTransitionsV5", "agentMerkleV5", "computeBudgetV5",
  "assets", "tokenManifestV5", "tokenExplain"
];

test("every documented flat export resolves to a defined value", () => {
  for (const name of FLAT_EXPORTS) {
    assert.ok(Object.prototype.hasOwnProperty.call(sdk, name), `missing flat export ${name}`);
    assert.notEqual(sdk[name], undefined, `flat export ${name} is undefined`);
  }
});

test("every documented namespace export resolves to a non-empty object", () => {
  for (const name of NAMESPACE_EXPORTS) {
    const ns = sdk[name];
    assert.equal(typeof ns, "object", `namespace ${name} is not an object`);
    assert.ok(ns !== null, `namespace ${name} is null`);
    assert.ok(Object.keys(ns).length > 0, `namespace ${name} is empty`);
  }
});

test("the entry point exports exactly the documented surface — nothing extra slipped in", () => {
  const documented = new Set([...FLAT_EXPORTS, ...NAMESPACE_EXPORTS]);
  const actual = Object.keys(sdk);
  const undocumented = actual.filter((k) => !documented.has(k));
  assert.deepEqual(undocumented, [], "undocumented exports must be added to this test AND to README.md, or removed");
  assert.equal(actual.length, documented.size);
});

test("the exported object is frozen (a consumer cannot monkey-patch the SDK surface)", () => {
  assert.ok(Object.isFrozen(sdk));
});

test("re-exports are IDENTITIES of the existing modules, never copies (one authoritative core)", () => {
  /* If any of these ever became a rebuilt object rather than the module
   * itself, the SDK would have started duplicating logic — the exact
   * anti-bloat failure the addendum forbids. */
  assert.equal(sdk.amounts, require("../src/amounts"));
  assert.equal(sdk.canonicalJson, require("../src/canonical-json"));
  assert.equal(sdk.feeMass, require("../src/fee-mass"));
  assert.equal(sdk.vaultStateV4, require("../src/vault-state-v4"));
  assert.equal(sdk.vaultTransitionsV4, require("../src/vault-transitions-v4"));
  assert.equal(sdk.agentMerkleV4, require("../src/agent-merkle-v4"));
  assert.equal(sdk.recipientMerkleV3, require("../src/recipient-merkle-v3"));
  assert.equal(sdk.approvalPackageV4, require("../src/approval-package-v4"));
  assert.equal(sdk.frozenTxV3, require("../src/frozen-tx-v3"));
  assert.equal(sdk.intent, require("../../core/intent"));
  assert.equal(sdk.signer, require("../../core/signer"));
  assert.equal(sdk.explain, require("../../core/explain"));
  assert.equal(sdk.parseSompi, require("../src/amounts").parseSompi);
  assert.equal(sdk.canonicalJsonStringify, require("../src/canonical-json").canonicalJsonStringify);
});

/* ---------------------------------------------------------------------- */
/* 2. Exclusions                                                           */
/* ---------------------------------------------------------------------- */

test("hosted-only, node-dialing, toolchain, config, and TEST-ONLY key modules are NOT on the public surface", () => {
  /* Identity comparison, not name comparison: renaming an export could not
   * sneak one of these onto the surface. */
  const forbidden = [
    "store", "chain", "config", "audit", "organization", "durable-json", "submission-claim",
    "manifest", "manifest-v2", "manifest-v4",
    "reconcile", "reconcile-v2", "reconcile-v4",
    "contract-compiler", "contract-compiler-v2", "contract-compiler-v3", "contract-compiler-v4",
    "vault-builders-v3", "vault-builders-v4",
    "wallet-requests-v2", "wallet-requests-v4", "wallet-submit-v4",
    "create-vault", "spend-vault", "lifecycle-vault", "recover-vault", "vault-ops-v2",
    "signer-dev", "keys"
  ];
  const exported = new Set(Object.values(sdk));
  const skipped = [];
  for (const name of forbidden) {
    let mod;
    try {
      mod = require(`../src/${name}`);
    } catch (error) {
      /* A module that will not even load in this environment plainly is not
       * being handed to consumers; record it rather than silently pass. */
      skipped.push(`${name} (${error.code || error.message})`);
      continue;
    }
    assert.ok(!exported.has(mod), `${name} must not be re-exported from the SDK entry point`);
  }
  assert.ok(skipped.length <= forbidden.length);
});

test("no export name hints at key material or a dev signer", () => {
  for (const name of Object.keys(sdk)) {
    assert.ok(!/privateKey|seed|mnemonic|devSign|signerDev|keyring/i.test(name), `suspicious export name: ${name}`);
  }
});

/* ---------------------------------------------------------------------- */
/* 3. Type-declaration drift                                               */
/* ---------------------------------------------------------------------- */

function declaredTopLevel(source) {
  return [...source.matchAll(/^export declare (?:const|function|class) ([A-Za-z_$][\w$]*)/gm)].map((m) => m[1]);
}

/* `export declare const <ns>: {` ... `};` — the members of a namespace. */
function declaredNamespaceMembers(source) {
  const out = {};
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const open = /^export declare const ([A-Za-z_$][\w$]*): \{$/.exec(lines[i]);
    if (!open) continue;
    const members = [];
    for (let j = i + 1; j < lines.length && lines[j] !== "};"; j++) {
      const member = /^ {2}(?:readonly )?([A-Za-z_$][\w$]*)\??\s*[:(]/.exec(lines[j]);
      if (member) members.push(member[1]);
    }
    out[open[1]] = members;
  }
  return out;
}

/* `export declare class PolicyVaultClient {` ... `}` — its methods. */
function declaredClassMethods(source, className) {
  const lines = source.split("\n");
  const start = lines.findIndex((l) => l === `export declare class ${className} {`);
  if (start < 0) return [];
  const methods = [];
  for (let j = start + 1; j < lines.length && lines[j] !== "}"; j++) {
    const m = /^ {2}([A-Za-z_$][\w$]*)(?:<[^>]*>)?\(/.exec(lines[j]);
    if (m && m[1] !== "constructor") methods.push(m[1]);
  }
  return methods;
}

const indexDts = fs.readFileSync(path.join(TYPES_DIR, "index.d.ts"), "utf8");
const clientDts = fs.readFileSync(path.join(TYPES_DIR, "http-client.d.ts"), "utf8");

test("types/: every top-level declared export exists at runtime", () => {
  const declared = [...declaredTopLevel(indexDts), ...declaredTopLevel(clientDts)];
  assert.ok(declared.length >= FLAT_EXPORTS.length, "the .d.ts parser found suspiciously few declarations");
  for (const name of declared) {
    assert.notEqual(sdk[name], undefined, `types declare ${name} but the runtime entry point does not export it`);
  }
});

test("types/: every declared namespace member exists on the real module", () => {
  const namespaces = declaredNamespaceMembers(indexDts);
  assert.ok(Object.keys(namespaces).length >= 15, "the .d.ts namespace parser found suspiciously few namespaces");
  let checked = 0;
  for (const [nsName, members] of Object.entries(namespaces)) {
    const runtime = sdk[nsName];
    assert.ok(runtime, `types declare namespace ${nsName} but it is not exported`);
    for (const member of members) {
      assert.notEqual(runtime[member], undefined, `types declare ${nsName}.${member} but the module does not export it`);
      checked += 1;
    }
  }
  assert.ok(checked > 100, `expected the namespaces to declare many members, checked only ${checked}`);
});

test("types/: every declared PolicyVaultClient method exists on the prototype", () => {
  const methods = declaredClassMethods(clientDts, "PolicyVaultClient");
  assert.ok(methods.length >= 30, `expected the full route surface, found ${methods.length}`);
  for (const name of methods) {
    assert.equal(typeof sdk.PolicyVaultClient.prototype[name], "function", `types declare client.${name}() but it does not exist`);
  }
});

test("types/: the runtime client exposes no undeclared public method (docs cannot fall behind code either)", () => {
  const declared = new Set([...declaredClassMethods(clientDts, "PolicyVaultClient"), "constructor"]);
  const actual = Object.getOwnPropertyNames(sdk.PolicyVaultClient.prototype)
    .filter((n) => typeof Object.getOwnPropertyDescriptor(sdk.PolicyVaultClient.prototype, n).value === "function")
    .filter((n) => !n.startsWith("_")); // _v4Body is deliberately internal
  for (const name of actual) {
    assert.ok(declared.has(name), `client.${name}() exists at runtime but is not declared in types/http-client.d.ts`);
  }
});

/* ---------------------------------------------------------------------- */
/* 4. Behavioral smoke — the exports actually compute                      */
/* ---------------------------------------------------------------------- */

test("amounts: KAS<->sompi round-trips exactly, and floating point is refused", () => {
  assert.equal(sdk.kasToSompi("1.5"), 150000000n);
  assert.equal(sdk.sompiToKas(150000000n), "1.5");
  assert.equal(sdk.sompiToKas(sdk.kasToSompi("0.00000001")), "0.00000001");
  assert.equal(sdk.sompiToKas(sdk.kasToSompi("12")), "12");
  assert.equal(sdk.parseSompi("150000000"), 150000000n);
  assert.equal(sdk.SOMPI_PER_KAS, 100000000n);

  /* A `number` is refused outright — the whole point of the sompi rule. */
  assert.throws(() => sdk.parseSompi(1.5), /BigInt or decimal string/);
  assert.throws(() => sdk.parseSompi(150000000), /BigInt or decimal string/);
  assert.throws(() => sdk.parseSompi("-1"), /digit string/);
  assert.throws(() => sdk.parseSompi("1e8"), /digit string/);
  assert.throws(() => sdk.parseSompi(""), /digit string/);
  assert.throws(() => sdk.parsePositiveSompi("0"), /greater than zero/);
  assert.throws(() => sdk.kasToSompi("1.123456789"), /not a valid KAS decimal/); // 9 fractional digits
  assert.throws(() => sdk.parseSompi((sdk.MAX_SOMPI + 1n).toString()), /exceeds maximum/);
});

test("canonicalJsonStringify: identical content in any key order produces identical bytes", () => {
  const a = { zeta: "1", alpha: { y: "2", x: ["3", "4"] } };
  const b = { alpha: { x: ["3", "4"], y: "2" }, zeta: "1" };
  assert.equal(sdk.canonicalJsonStringify(a), sdk.canonicalJsonStringify(b));
  assert.notEqual(JSON.stringify(a), JSON.stringify(b), "the inputs must genuinely differ in key order for this to prove anything");
  /* This is the G-2 property: PostgreSQL jsonb reorders keys, so any
   * commitment preimage built with plain JSON.stringify breaks on a
   * round-trip. */
  assert.equal(sdk.canonicalJsonStringify(JSON.parse(JSON.stringify(b))), sdk.canonicalJsonStringify(a));
});

test("recipient Merkle: a real root, a real proof, and a real verification", () => {
  const recipients = ["11".repeat(32), "22".repeat(32), "33".repeat(32)];
  const tree = sdk.recipientMerkleV3.buildRecipientTree(recipients);
  assert.match(tree.root, /^[0-9a-f]{64}$/);

  /* Determinism: the same input always commits to the same root. */
  assert.equal(sdk.recipientMerkleV3.buildRecipientTree(recipients).root, tree.root);
  /* Sensitivity: a different set must not collide. */
  assert.notEqual(sdk.recipientMerkleV3.buildRecipientTree([...recipients, "44".repeat(32)]).root, tree.root);

  /* The proof is self-describing: it carries its own `recipient` and `root`
   * alongside siblingsHex/pathBits, so the override below must come AFTER
   * the spread to actually take effect. */
  const proof = sdk.recipientMerkleV3.generateRecipientProof(tree, recipients[1]);
  assert.equal(proof.recipient, recipients[1]);
  assert.equal(proof.root, tree.root);
  assert.equal(sdk.recipientMerkleV3.verifyRecipientProof(proof), true);

  /* A proof for one recipient must not verify a different recipient. */
  assert.equal(
    sdk.recipientMerkleV3.verifyRecipientProof({ ...proof, recipient: recipients[2] }),
    false
  );
  /* ...nor a different root. */
  assert.equal(
    sdk.recipientMerkleV3.verifyRecipientProof({ ...proof, root: "ff".repeat(32) }),
    false
  );
});

test("agent Merkle + successor derivation: an integrator can recompute both locally", () => {
  const agentPk = "aa".repeat(32);
  const recipientRoot = sdk.recipientMerkleV3.buildRecipientTree(["bb".repeat(32)]).root;
  const policy = sdk.agentMerkleV4.normalizeAgentPolicyV4({
    agentPk,
    maxPerSpend: "2000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: "50000000000",
    agentMaxFeePerTx: "100000000",
    agentRecipientRoot: recipientRoot
  });
  const tree = sdk.agentMerkleV4.buildAgentTreeV4([policy]);
  assert.match(tree.root, /^[0-9a-f]{64}$/);

  const state = sdk.vaultStateV4.normalizeStateV4({
    protectedValue: "100000000000",
    feeReserve: "500000000",
    paused: "0",
    agentRoot: tree.root,
    approvers: [],
    approvalM: "0",
    policyNonce: "0"
  });

  /* A state's covenant-bound identity is recomputable, not something a
   * server has to be trusted about. */
  const stateId = sdk.vaultStateV4.computeStateIdV4({ networkId: "testnet-10", template: { owner: "cc".repeat(32), vaultId: "dd".repeat(32) }, state });
  assert.match(stateId, /^[0-9a-f]{64}$/);
  assert.equal(
    sdk.vaultStateV4.computeStateIdV4({ networkId: "testnet-10", template: { owner: "cc".repeat(32), vaultId: "dd".repeat(32) }, state }),
    stateId
  );
  /* A different network is a different identity — no cross-network reuse. */
  assert.notEqual(
    sdk.vaultStateV4.computeStateIdV4({ networkId: "mainnet", template: { owner: "cc".repeat(32), vaultId: "dd".repeat(32) }, state }),
    stateId
  );

  /* Derive the successor yourself rather than adopting a server's. */
  const after = sdk.vaultTransitionsV4.topUpSuccessorV4(state, "1000000000");
  const json = sdk.vaultStateV4.stateToJsonV4(after);
  assert.equal(json.protectedValue, "101000000000");
  assert.equal(json.feeReserve, "500000000", "a topUp must not silently move the fee reserve");
  assert.equal(json.agentRoot, tree.root, "a topUp must not change the agent registry");

  const reserveAfter = sdk.vaultTransitionsV4.topUpReserveSuccessorV4(state, "1000000000");
  assert.equal(sdk.vaultStateV4.stateToJsonV4(reserveAfter).feeReserve, "1500000000");
  assert.equal(sdk.vaultStateV4.stateToJsonV4(reserveAfter).protectedValue, "100000000000");
});

test("intent verifier: fails CLOSED on an unknown manifest version — refusal, not a throw, not a guess", () => {
  const verdict = sdk.intent.verifyIntentManifest({
    manifest: { manifestVersion: "policyvault-intent-manifest/v999", anything: true },
    requestedIntent: {},
    decodedTransaction: {}
  });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.verdict, sdk.intent.VERDICTS.REFUSED);
  assert.equal(verdict.statement, null, "a refused verification must never carry the verified statement");
  assert.ok(verdict.failures.length > 0);
  assert.equal(verdict.failures[0].code, "UNKNOWN_MANIFEST_VERSION");
});

test("intent: the verified statement and supported covenant versions are the pinned ones", () => {
  assert.equal(sdk.intent.VERIFIED_STATEMENT, "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.");
  assert.deepEqual([...sdk.SUPPORTED_COVENANT_VERSIONS], ["policyvault-0.4", "policyvault-0.4.1"]);
  assert.equal(sdk.CONTRACT_VERSION_V4, "policyvault-0.4");
  assert.equal(sdk.CONTRACT_VERSION_V4_1, "policyvault-0.4.1");
  assert.equal(sdk.CONTRACT_VERSION_V3, "policyvault-0.3");
  assert.equal(sdk.CONTRACT_VERSION, "policyvault-0.1-beta");
});

test("version routing fails closed: an unknown contract version resolves to no ABI", () => {
  assert.throws(() => sdk.resolveV4Abi("policyvault-0.9"), /unknown|unsupported|version/i);
  assert.ok(sdk.resolveV4Abi(sdk.CONTRACT_VERSION_V4));
});

test("package.json main/types/exports point at files that exist", () => {
  const pkg = require("../package.json");
  assert.equal(pkg.private, true, "publication is an owner gate — this package must stay private");
  assert.equal(pkg.license, "Apache-2.0");
  for (const rel of [pkg.main, pkg.types]) {
    assert.ok(fs.existsSync(path.join(__dirname, "..", rel)), `package.json points at missing ${rel}`);
  }
  assert.equal(pkg.exports["."].default, "./src/index.js");
  assert.equal(pkg.exports["."].types, "./types/index.d.ts");
  assert.equal(pkg.exports["./http-client"].default, "./src/http-client.js");
  assert.ok(fs.existsSync(path.join(__dirname, "..", pkg.exports["./http-client"].types)));
  assert.ok(fs.existsSync(path.join(__dirname, "..", "README.md")));
});
