"use strict";

/*
 * CROSS-RUNTIME EQUIVALENCE — the v0.7 PRESENTATION and SIGNER-PATH modules
 * (gate I3/I4): core/explain/org-root-explain.js,
 * core/signer/org-root-slot-v7.js and core/model/fee-mass-v7.js, plus their
 * transitive core dependencies.
 *
 * Why this matters. What an owner READS before signing, what a signer
 * CHECKS before returning a slot signature, and what a fee display SAYS a
 * transaction will cost must be identical in every runtime that can hold an
 * owner key — a browser tab, a mobile signer, an air-gapped laptop, a Node
 * service. A rendering that differed between runtimes would mean two owners of
 * the same organization approved two different descriptions of one
 * transaction, and a refusal that fired in Node but not in a browser would be
 * a silent hole in exactly the layer that exists to prevent that.
 *
 * Method (identical to the sibling probes): each module is loaded into a fresh
 * V8 context shaped like a browser page — `window` as the global, NO require /
 * module / process / Buffer, and the exact crypto shim a real browser gets —
 * and only final primitive outputs are compared.
 *
 * SCOPE NOTE: the v0.7 modules are deliberately NOT part of the reviewed
 * web/core-bundle.js MODULES list (I2-D3), so this is a forward-looking
 * portability probe on the COMMITTED SOURCE, not a claim about the shipped
 * bundle.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { loadCoreFilesInSandbox, rehome, rehomeInto } = require("../sandbox.js");
const { stringifyBigInts } = require("../vectors.js");

/* The transitive closure of the three modules under test, in load order. */
const V7_PRESENTATION_FILES = Object.freeze([
  "core/intent/canonical.js",
  "core/model/own-get.js",
  "core/model/canonical-json.js",
  "core/assets/blake2b.js",
  "core/model/token-amounts.js",
  "core/assets/kcc20.js",
  "core/assets/descriptor.js",
  "core/assets/index.js",
  "core/model/amounts.js",
  "core/model/contract-version.js",
  "core/model/vault-state.js",
  "core/model/owner-set-v7.js",
  "core/model/vault-state-v7-root.js",
  "core/model/vault-state-v5.js",
  "core/model/vault-state-v7.js",
  "core/model/agent-merkle-v5.js",
  "core/model/recipient-merkle-v3.js",
  "core/intent/org-root-manifest-v7.js",
  "core/intent/root-script-v7.js", // rc20 review R5-04: the verifier rebuilds the frozen root script (STALE ASSUMPTION: new dependency)
  "core/intent/vault-script-v7.js", // Codex checkpoint 6 (UX-02 / UX-13): the verifier rebuilds the rooted-vault successor script (STALE ASSUMPTION: new dependency)
  "core/intent/vault-script-v7-kas.js", // v0.7 enablement (2026-09-10): the signer accepts the org-root-KAS manifest family
  "core/intent/org-root-manifest-v7-kas.js", // v0.7 enablement (2026-09-10): the signer accepts the org-root-KAS manifest family
  "core/model/vault-state-v7-kas.js",
  "core/model/vault-transitions-v7-kas.js",
  "core/model/compute-budget-v7-kas.js",
  "core/model/vault-state-v4.js",
  "core/model/vault-transitions-v4.js",
  "core/model/agent-merkle-v4.js",
  "core/model/compute-budget-v4.js",
  "core/model/compute-budget-v7.js", // Codex checkpoint 6 (UX-02 / UX-13): the verifier DERIVES every compute budget (STALE ASSUMPTION: new dependency)
  "core/explain/kas.js",
  "core/intent/token-manifest-v5.js",
  "core/explain/token-explain.js",
  "core/explain/org-root-explain.js",
  "core/explain/org-root-kas-explain.js", // v0.7 enablement (2026-09-10)
  "core/signer/errors.js",
  "core/signer/interface.js",
  /* policyvault-signer/2 portable leaves (Wave 2, Track G: the slot module gained a v2 request path) */
  "core/signer/v2/errors.js",
  "core/signer/v2/interface.js",
  "core/signer/org-root-slot-v7.js",
  "core/model/fee-mass.js",
  "core/model/storage-mass.js",
  "core/model/fee-mass-v7.js"
]);

const sandbox = loadCoreFilesInSandbox(V7_PRESENTATION_FILES);

const explainNode = require("../../explain/org-root-explain.js");
const explainSandbox = sandbox.require("core/explain/org-root-explain.js");
const slotNode = require("../../signer/org-root-slot-v7.js");
const slotSandbox = sandbox.require("core/signer/org-root-slot-v7.js");
const feeNode = require("../../model/fee-mass-v7.js");
const feeSandbox = sandbox.require("core/model/fee-mass-v7.js");

const explainFixture = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "explain", "test", "fixtures", "v7-org-root-manifests.json"), "utf8"));
const slotFixture = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "signer", "test", "fixtures", "v7-org-root-slot.json"), "utf8"));

const NOW = 1_700_000_000_000;
const SOON = NOW + 3_600_000;
const slotSig = (b) => b.toString(16).padStart(2, "0").repeat(64) + "01";

/* ------------------------------------------------------------------ */

for (const relPath of ["core/explain/org-root-explain.js", "core/signer/org-root-slot-v7.js", "core/model/fee-mass-v7.js"]) {
  test(`smoke: ${relPath} loads in the browser-like sandbox with the SAME export key set as Node`, () => {
    const nodeMod = require(`../../../${relPath}`);
    const sandboxMod = sandbox.require(relPath);
    assert.deepEqual(Object.keys(sandboxMod).sort(), Object.keys(nodeMod).sort());
  });
}

/* ---- the explanation an owner reads ---- */

for (const f of explainFixture.manifests) {
  test(`EQUIVALENCE[explain ${f.name}]: structured() and humanReadable() agree node vs browser-like runtime`, () => {
    const docNode = explainNode.structured({ manifest: f.manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts });
    const linesNode = explainNode.humanReadable({ manifest: f.manifest, descriptors: f.descriptors, redeemScripts: f.redeemScripts });
    assert.equal(docNode.verdict, "VERIFIED_EXACT", `${f.name}: sanity`);

    const manifestForSandbox = rehomeInto(sandbox.global, f.manifest);
    const descriptorsForSandbox = rehomeInto(sandbox.global, f.descriptors);
    const redeemForSandbox = rehomeInto(sandbox.global, f.redeemScripts || {});
    const docSandbox = explainSandbox.structured({ manifest: manifestForSandbox, descriptors: descriptorsForSandbox, redeemScripts: redeemForSandbox });
    const linesSandbox = explainSandbox.humanReadable({ manifest: manifestForSandbox, descriptors: descriptorsForSandbox, redeemScripts: redeemForSandbox });

    assert.equal(docSandbox.verdict, "VERIFIED_EXACT", `${f.name}: the browser-like runtime must reach the SAME verdict`);
    assert.deepEqual(rehome(docSandbox), rehome(docNode), `${f.name}: the structured document must be value-identical`);
    assert.deepEqual([...linesSandbox], [...linesNode], `${f.name}: the rendered lines must be byte-identical, in order`);
  });
}

test("EQUIVALENCE[explain]: a REFUSED manifest renders the identical DO-NOT-SIGN lines in both runtimes", () => {
  const bad = { ...explainFixture.manifests[0].manifest, manifestHash: "ee".repeat(32) };
  const docNode = explainNode.structured({ manifest: bad });
  const linesNode = explainNode.humanReadable({ manifest: bad });
  assert.equal(docNode.verdict, "REFUSED");

  const forSandbox = rehomeInto(sandbox.global, bad);
  const docSandbox = explainSandbox.structured({ manifest: forSandbox });
  const linesSandbox = explainSandbox.humanReadable({ manifest: forSandbox });

  assert.equal(docSandbox.verdict, "REFUSED", "a refusal that fired in Node and passed in a browser would be a silent hole");
  assert.deepEqual(rehome(docSandbox), rehome(docNode));
  assert.deepEqual([...linesSandbox], [...linesNode]);
  assert.equal(linesSandbox[0], "!! DO NOT SIGN !!");

  /* the standalone rooted-vault manifest refuses identically in both */
  const standalone = explainFixture.standaloneRootedVaultManifest;
  const a = explainNode.structured({ manifest: standalone });
  const b = explainSandbox.structured({ manifest: rehomeInto(sandbox.global, standalone) });
  assert.deepEqual(rehome(b), rehome(a));
  assert.deepEqual(rehome(b.refusal.failingChecks), ["verifyWithinParent"]);
});

/* ---- the signer slot path ---- */

test("EQUIVALENCE[slot path]: a request built in Node verifies IDENTICALLY in the browser-like runtime", () => {
  const request = slotNode.createRootSlotSigningRequest({
    manifest: slotFixture.primary.manifest,
    slot: 1,
    expectedSignerAddress: slotFixture.ownerAddresses[0],
    unsignedSafeJson: slotFixture.primary.unsignedSafeJson,
    rootInputIndex: slotFixture.rootInputIndex,
    expiresAtMs: SOON,
    nowMs: NOW
  });

  /* the signer half runs in the OTHER runtime, on the same JSON */
  const requestForSandbox = rehomeInto(sandbox.global, request);
  const signed = (() => {
    const j = JSON.parse(request.unsignedSafeJson);
    j.inputs[request.root.inputIndex].signatureScript = `41${slotSig(0x11)}`;
    return JSON.stringify(j);
  })();

  const responseNode = slotNode.buildRootSlotSignatureResponse({ request, signedSafeJson: signed, signedAtMs: NOW + 1000 });
  const responseSandbox = slotSandbox.buildRootSlotSignatureResponse({ request: requestForSandbox, signedSafeJson: signed, signedAtMs: NOW + 1000 });
  assert.deepEqual(rehome(responseSandbox), rehome(responseNode), "the response envelope must be value-identical");

  const ownerSetForSandbox = rehomeInto(sandbox.global, slotFixture.ownerSet);
  const vNode = slotNode.verifyRootSlotSignatureResponse({ request, response: responseNode, ownerSet: slotFixture.ownerSet, nowMs: NOW + 2000 });
  const vSandbox = slotSandbox.verifyRootSlotSignatureResponse({ request: requestForSandbox, response: rehomeInto(sandbox.global, responseNode), ownerSet: ownerSetForSandbox, nowMs: NOW + 2000 });
  assert.deepEqual(rehome(vSandbox), rehome(vNode));

  /* and the collected 780-byte blob is byte-identical */
  const request2 = slotNode.createRootSlotSigningRequest({
    manifest: slotFixture.primary.manifest,
    slot: 2,
    expectedSignerAddress: slotFixture.ownerAddresses[1],
    unsignedSafeJson: slotFixture.primary.unsignedSafeJson,
    rootInputIndex: slotFixture.rootInputIndex,
    expiresAtMs: SOON,
    nowMs: NOW
  });
  const signed2 = (() => {
    const j = JSON.parse(request2.unsignedSafeJson);
    j.inputs[request2.root.inputIndex].signatureScript = `41${slotSig(0x22)}`;
    return JSON.stringify(j);
  })();
  const response2 = slotNode.buildRootSlotSignatureResponse({ request: request2, signedSafeJson: signed2, signedAtMs: NOW + 1000 });
  const pairs = [
    { request, response: responseNode },
    { request: request2, response: response2 }
  ];
  const cNode = slotNode.collectRootSlotApprovals({ ownerSet: slotFixture.ownerSet, actionName: "authorize", pairs, nowMs: NOW + 2000 });
  const cSandbox = slotSandbox.collectRootSlotApprovals({ ownerSet: ownerSetForSandbox, actionName: "authorize", pairs: rehomeInto(sandbox.global, pairs), nowMs: NOW + 2000 });
  assert.equal(cSandbox.blobHex, cNode.blobHex, "the 780-byte owner blob must be byte-identical across runtimes");
  assert.deepEqual(rehome(stringifyBigInts(cSandbox)), rehome(stringifyBigInts(cNode)));
});

test("EQUIVALENCE[slot path]: every hostile refusal fires with the SAME code and reason in both runtimes", () => {
  const request = slotNode.createRootSlotSigningRequest({
    manifest: slotFixture.primary.manifest,
    slot: 1,
    expectedSignerAddress: slotFixture.ownerAddresses[0],
    unsignedSafeJson: slotFixture.primary.unsignedSafeJson,
    rootInputIndex: slotFixture.rootInputIndex,
    expiresAtMs: SOON,
    nowMs: NOW
  });
  const requestForSandbox = rehomeInto(sandbox.global, request);
  const signed = (() => {
    const j = JSON.parse(request.unsignedSafeJson);
    j.inputs[request.root.inputIndex].signatureScript = `41${slotSig(0x11)}`;
    return JSON.stringify(j);
  })();
  const good = slotNode.buildRootSlotSignatureResponse({ request, signedSafeJson: signed, signedAtMs: NOW + 1000 });

  const rows = [
    ["wrong network", { ...good, network: "mainnet" }, NOW + 1],
    ["wrong slot key", { ...good, slot: { ...good.slot, publicKey: "ee".repeat(32) } }, NOW + 1],
    ["different transaction", { ...good, txId: "cc".repeat(32) }, NOW + 1],
    ["different manifest", { ...good, manifestHash: "dd".repeat(32) }, NOW + 1],
    ["moved root outpoint", { ...good, root: { ...good.root, outpoint: { transactionId: "0e".repeat(32), index: 0 } } }, NOW + 1],
    ["different signer identity", { ...good, signerAddress: slotFixture.ownerAddresses[2] }, NOW + 1],
    ["non-ALL sighash", { ...good, sighashType: 2 }, NOW + 1],
    ["stale request", good, SOON]
  ];

  const capture = (fn) => {
    try {
      fn();
      return { threw: false };
    } catch (e) {
      return { threw: true, signerCode: e.signerCode ?? null, reason: e.details ? e.details.reason : null };
    }
  };

  for (const [label, response, nowMs] of rows) {
    const a = capture(() => slotNode.verifyRootSlotSignatureResponse({ request, response, ownerSet: slotFixture.ownerSet, nowMs }));
    const b = capture(() =>
      slotSandbox.verifyRootSlotSignatureResponse({
        request: requestForSandbox,
        response: rehomeInto(sandbox.global, response),
        ownerSet: rehomeInto(sandbox.global, slotFixture.ownerSet),
        nowMs
      })
    );
    assert.equal(a.threw, true, `${label}: must refuse in Node`);
    assert.deepEqual(b, a, `${label}: the browser-like runtime must refuse with the SAME code and reason`);
  }
});

/* ---- the fee an owner is shown ---- */

test("EQUIVALENCE[fee model]: every measured shape and the whole threshold curve agree node vs browser-like runtime", () => {
  /* rehome the WHOLE array: a sandbox-realm Array.prototype.map returns a
   * sandbox-realm array, which deepStrictEqual would reject on prototype
   * identity alone even when every value matches. */
  const nodeFees = rehome(stringifyBigInts(feeNode.allShapeFees()));
  const sandboxFees = rehome(stringifyBigInts(feeSandbox.allShapeFees()));
  assert.equal(sandboxFees.length, nodeFees.length);
  assert.deepEqual(sandboxFees, nodeFees, "a fee displayed in a browser must equal the fee computed in Node");

  assert.deepEqual(rehome(stringifyBigInts(feeSandbox.rootThresholdCurve())), rehome(stringifyBigInts(feeNode.rootThresholdCurve())));
  assert.equal(feeSandbox.ROOT_FEE_CROSSOVER_ACTIVE_SLOTS, feeNode.ROOT_FEE_CROSSOVER_ACTIVE_SLOTS);

  const profile = { vaults: 2, ownerOps: 3, rootOnlyActions: 1, delegateSpends: 10, heartbeats: 4, activeOwnerSlots: 5 };
  assert.deepEqual(
    rehome(stringifyBigInts(feeSandbox.organizationCost(rehomeInto(sandbox.global, profile)))),
    rehome(stringifyBigInts(feeNode.organizationCost(profile)))
  );

  /* unknown shapes fail closed in BOTH runtimes */
  assert.throws(() => feeNode.feeForLabel("no such shape"), /failing closed/);
  assert.throws(() => feeSandbox.feeForLabel("no such shape"), /failing closed/);
});
