"use strict";

/*
 * Cross-runtime equivalence: the CLI signer adapter's core-overlap path
 * (core/signer/adapters/cli), Node direct vs the browser bundle.
 *
 * core/signer/adapters/cli/adapter.js is a REAL, materially different
 * (headless, offline, keyfile-custodied) Universal Signer Interface
 * implementation — the completion standard's "signer independence" proof
 * (item 4). Its own conformance/behavior against a REAL kaspa-wasm module
 * is proven by core/signer/adapters/cli/test/*.test.js and is explicitly
 * OUT of scope here: this mission is deterministic and offline (no
 * network, no docker, no vendored wasm dependency), and kaspa-wasm is
 * loaded LAZILY (only inside connect()/signMessage()/signTransaction()),
 * so the actual signing path cannot be exercised without it.
 *
 * What DOES overlap the portable, comparable, cross-runtime surface —
 * and is exercised here against the REAL adapter module, not a mock — is
 * everything describe()/detect() touch before any kaspa-wasm call: the
 * capability descriptor this genuinely different signer kind produces,
 * and how core/signer/interface.js (the same module the browser bundle
 * embeds) validates and negotiates against it. This is the concrete
 * cross-runtime claim: "a real non-browser, non-KasWare signer's
 * capability descriptor is understood identically by Node and by the
 * browser's own copy of the interface."
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCommittedBundleInBrowserGlobal, rehome, rehomeInto } = require("../sandbox.js");
const { CAPABILITY_NEGOTIATION_REQUIREMENTS } = require("../vectors.js");

const nodeInterface = require("../../signer/interface.js");
const { createCliSignerAdapter, assertOperatingNetwork } = require("../../signer/adapters/cli/adapter.js");

const { PolicyVaultCore, global: sandboxGlobal } = loadCommittedBundleInBrowserGlobal();

/* A synthetic, never-read keyfile path: describe()/detect() never touch
 * the filesystem for content (detect() only stats; describe() does not
 * touch the filesystem at all), so this never needs a real keyfile or
 * kaspa-wasm. */
const SYNTHETIC_KEYFILE_PATH = "/nonexistent/policyvault-crossruntime-probe.keyfile.json";

test("REAL CLI ADAPTER: describe() output validates identically through node vs bundle core/signer/interface.js", () => {
  const adapter = createCliSignerAdapter({ keyfilePath: SYNTHETIC_KEYFILE_PATH, network: "testnet-10" });
  assert.equal(adapter.detect(), false, "sanity: the synthetic path must not exist");

  const rawDescriptor = adapter.describe();
  assert.equal(rawDescriptor.kind, "cli", "sanity: this really is the CLI adapter's own descriptor, not KasWare's");

  const normNode = nodeInterface.validateCapabilityDescriptor(rawDescriptor);
  const normBundle = PolicyVaultCore.signerInterface.validateCapabilityDescriptor(rehomeInto(sandboxGlobal, rawDescriptor));
  assert.deepEqual(rehome(normBundle), rehome(normNode), "the CLI signer's real capability descriptor must normalize identically in both runtimes");

  const regNode = nodeInterface.validateAdapter(adapter);
  assert.equal(regNode.descriptor.provider, "cli-keyfile");
  assert.deepEqual(rehome(regNode.descriptor), rehome(normNode), "validateAdapter's descriptor must match validateCapabilityDescriptor's own normalization (Node, sanity)");
});

test("REAL CLI ADAPTER: capability negotiation against its real descriptor agrees node vs bundle over the requirement battery", () => {
  const adapter = createCliSignerAdapter({ keyfilePath: SYNTHETIC_KEYFILE_PATH, network: "testnet-10" });
  const rawDescriptor = adapter.describe();
  const normNode = nodeInterface.validateCapabilityDescriptor(rawDescriptor);
  const normBundle = PolicyVaultCore.signerInterface.validateCapabilityDescriptor(rehomeInto(sandboxGlobal, rawDescriptor));

  for (const requirement of CAPABILITY_NEGOTIATION_REQUIREMENTS) {
    const rNode = nodeInterface.negotiateCapabilities(normNode, requirement);
    const rBundle = PolicyVaultCore.signerInterface.negotiateCapabilities(normBundle, rehomeInto(sandboxGlobal, requirement));
    assert.deepEqual(rehome(rBundle), rehome(rNode), `requirement ${JSON.stringify(requirement)}`);
  }

  /* This adapter declares testnet-10 ONLY (constructed above without
   * allowMainnet) — negotiating "mainnet" must fail the SAME way in both
   * runtimes: a concrete, adapter-specific (not just vocabulary-level)
   * cross-runtime agreement. */
  const mainnetReq = { network: "mainnet" };
  const rNode = nodeInterface.negotiateCapabilities(normNode, mainnetReq);
  const rBundle = PolicyVaultCore.signerInterface.negotiateCapabilities(normBundle, rehomeInto(sandboxGlobal, mainnetReq));
  assert.equal(rNode.ok, false);
  assert.equal(rNode.code, "WRONG_NETWORK");
  assert.deepEqual(rehome(rBundle), rehome(rNode));
});

test("REAL CLI ADAPTER: a mainnet-constructed descriptor (dual-unlock satisfied) also negotiates identically in both runtimes", () => {
  const prior = process.env.PV_CLI_SIGNER_ALLOW_MAINNET;
  process.env.PV_CLI_SIGNER_ALLOW_MAINNET = "1";
  try {
    const adapter = createCliSignerAdapter({ keyfilePath: SYNTHETIC_KEYFILE_PATH, network: "mainnet", allowMainnet: true });
    const rawDescriptor = adapter.describe();
    assert.deepEqual(rawDescriptor.networks, ["mainnet"]);

    const normNode = nodeInterface.validateCapabilityDescriptor(rawDescriptor);
    const normBundle = PolicyVaultCore.signerInterface.validateCapabilityDescriptor(rehomeInto(sandboxGlobal, rawDescriptor));
    assert.deepEqual(rehome(normBundle), rehome(normNode));

    const rNode = nodeInterface.negotiateCapabilities(normNode, { network: "mainnet" });
    const rBundle = PolicyVaultCore.signerInterface.negotiateCapabilities(normBundle, { network: "mainnet" });
    assert.equal(rNode.ok, true);
    assert.deepEqual(rehome(rBundle), rehome(rNode));
  } finally {
    if (prior === undefined) delete process.env.PV_CLI_SIGNER_ALLOW_MAINNET;
    else process.env.PV_CLI_SIGNER_ALLOW_MAINNET = prior;
  }
});

test("REAL CLI ADAPTER (Node-only gate, documented as such): the mainnet dual-unlock itself is CLI-specific and not part of the bundled surface", () => {
  /* assertOperatingNetwork reads process.env directly (PV_CLI_SIGNER_
   * ALLOW_MAINNET) — a Node/CLI-operator concept with no browser
   * analogue, and core/signer/adapters/cli is correctly NOT part of
   * web/tools/build-core-bundle.js's MODULES list. This test exists to
   * make that scope boundary explicit rather than silently assumed: the
   * CROSS-RUNTIME claim in this file is about the DESCRIPTOR the adapter
   * produces (proven above), never about this gate itself running in a
   * browser. */
  assert.throws(() => assertOperatingNetwork("mainnet", false), (e) => e.signerCode === "WRONG_NETWORK");
  assert.equal(typeof PolicyVaultCore.signerInterface !== "undefined" && PolicyVaultCore.signerInterface.assertOperatingNetwork, undefined);
});
