"use strict";

/*
 * MOBILE UNIT — ANTI-DRIFT between the mobile QR/air-gap portable layer
 * and the Universal Signer Interface v2 air-gap adapter.
 *
 * Two modules now speak the offline signer's document schemas:
 *
 *   mobile/www/js/portable/airgap.js   the shipped mobile builder/parser
 *                                      (with its independent second
 *                                      refusal: no signing document can
 *                                      exist without a PASSING on-device
 *                                      verification bound to the exact
 *                                      bytes)
 *   core/signer/v2/adapters/airgap.js  the v2 transport adapter, which
 *                                      drives the SAME documents through
 *                                      the interface's gates
 *
 * Two implementations of one frozen schema is exactly how a schema drifts.
 * This suite pins them together: identical format ids, identical closed
 * key sets in identical order, a request document that is field-for-field
 * the same, and responses that both modules accept or both refuse.
 *
 * Claim label: UNIT-TESTED. No camera, no share sheet, and no real
 * offline signer process is exercised here — those limits are unchanged
 * and are stated in the mobile scaffold record.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const mobileAirgap = require("../www/js/portable/airgap.js");
const coreAirgap = require("../../core/signer/v2/adapters/airgap.js");
const v2 = require("../../core/signer/v2");

const NETWORK = "testnet-10";
const SIGNER = "kaspatest:qqofflinesignerv2000000000000000000000000000000000000000000000";
const UNSIGNED = JSON.stringify({ id: "a".repeat(64), version: 0, inputs: [{ index: 0 }], outputs: [] });
const SIGNED = JSON.stringify({ id: "a".repeat(64), version: 0, inputs: [{ index: 0, signatureScript: "41ff" }], outputs: [] });
const OTHER = JSON.stringify({ id: "b".repeat(64), version: 0, inputs: [], outputs: [] });

/* the shape mobile's independent second refusal requires */
const PASSING_VERIFICATION = Object.freeze({
  ok: true,
  verdict: "VERIFIED_EXACT",
  unsignedSafeJson: UNSIGNED,
  txId: "a".repeat(64)
});

function coreRequest() {
  return v2.createTransactionSigningRequestV2({
    unsignedSafeJson: UNSIGNED,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: NETWORK,
    expectedSignerAddress: SIGNER,
    ttlMs: 600000
  });
}

function signedDocument(overrides = {}) {
  return JSON.stringify({
    format: "policyvault-cli-signer-signed-transaction/1",
    requestId: "0".repeat(32),
    kind: "sign-transaction",
    network: NETWORK,
    address: SIGNER,
    signedSafeJson: SIGNED,
    ...overrides
  });
}

test("both modules restate the SAME frozen offline-signer formats and closed key sets, in the same order", () => {
  assert.equal(coreAirgap.SIGNING_REQUEST_FORMAT, mobileAirgap.SIGNING_REQUEST_FORMAT);
  assert.equal(coreAirgap.SIGNED_TX_FORMAT, mobileAirgap.SIGNED_TX_FORMAT);
  assert.equal(coreAirgap.SIGNATURE_FORMAT, mobileAirgap.AUTH_SIGNATURE_FORMAT);
  assert.deepEqual([...coreAirgap.SIGNING_REQUEST_KEYS], [...mobileAirgap.SIGNING_REQUEST_KEYS]);
  assert.deepEqual([...coreAirgap.SIGNED_TX_KEYS], [...mobileAirgap.SIGNED_TX_KEYS]);
  assert.deepEqual([...coreAirgap.SIGNATURE_KEYS], [...mobileAirgap.AUTH_SIGNATURE_KEYS]);
});

test("the request documents are field-for-field identical, key order included", () => {
  const fromMobile = mobileAirgap.buildSigningRequestDocument({
    request: { transaction: { unsignedSafeJson: UNSIGNED, signInputs: [{ index: 0, sighashType: 1 }] } },
    verification: PASSING_VERIFICATION,
    network: NETWORK,
    expectedSignerAddress: SIGNER
  });
  assert.equal(fromMobile.ok, true, fromMobile.detail);

  const fromCore = coreAirgap.buildSigningRequestDocument(coreRequest());

  assert.deepEqual(Object.keys(fromCore), Object.keys(fromMobile.document), "identical key ORDER — the emitted document must be deterministic");
  /* The comparison is over the WIRE FORM, which is the actual contract: a
   * document crosses the gap as JSON text. (The mobile builder hardens its
   * signInputs entries as null-prototype objects, so a strict structural
   * deep-equal against ordinary objects would compare JavaScript identity
   * semantics rather than the bytes the offline signer will read.) */
  assert.deepEqual(JSON.parse(JSON.stringify(fromCore)), JSON.parse(fromMobile.documentText));
  /* plain serialization on BOTH sides — deliberately not a replacer array,
   * which is the very construct the regression below exists for */
  assert.equal(JSON.stringify(fromCore), JSON.stringify(fromMobile.document));
});

test("REGRESSION: the emitted document TEXT carries the per-input signing metadata (and the /2 manifest) intact", () => {
  /* Defect found by this suite: the builder serialized its document with a
   * JSON.stringify replacer ARRAY of the closed key list. A replacer array
   * filters property names at EVERY nesting level, so the text that
   * actually crossed the gap carried `signInputs: [{}]` — and, in the /2
   * VERIFYING form, `manifest: {}` — while the in-memory `document` object
   * looked correct. The offline signer refuses such a document (fail
   * closed), but the flow was broken, and the /2 form's independent
   * offline verification was inert on the wire. This test reads the TEXT,
   * which is the only thing the signer ever sees. */
  const manifest = { version: "policyvault-intent-manifest/1", txId: "a".repeat(64) };
  const built = mobileAirgap.buildSigningRequestDocument({
    request: { transaction: { unsignedSafeJson: UNSIGNED, signInputs: [{ index: 0, sighashType: 1 }] }, manifest },
    verification: PASSING_VERIFICATION,
    network: NETWORK,
    expectedSignerAddress: SIGNER
  });
  assert.equal(built.ok, true, built.detail);
  const onTheWire = JSON.parse(built.documentText);
  assert.equal(onTheWire.format, mobileAirgap.SIGNING_REQUEST_FORMAT_V2);
  assert.deepEqual(onTheWire.signInputs, [{ index: 0, sighashType: 1 }], "signing metadata must survive serialization");
  assert.deepEqual(onTheWire.manifest, manifest, "the intent manifest must survive serialization");
  assert.deepEqual(Object.keys(onTheWire), [...mobileAirgap.SIGNING_REQUEST_KEYS_V2], "closed key set and order preserved");

  const plain = mobileAirgap.buildSigningRequestDocument({
    request: { transaction: { unsignedSafeJson: UNSIGNED, signInputs: [{ index: 0, sighashType: 1 }, { index: 2, sighashType: 1 }] } },
    verification: PASSING_VERIFICATION,
    network: NETWORK,
    expectedSignerAddress: SIGNER
  });
  assert.deepEqual(JSON.parse(plain.documentText).signInputs, [{ index: 0, sighashType: 1 }, { index: 2, sighashType: 1 }]);
});

test("REGRESSION: the offline signer's own request parser accepts the mobile document TEXT", () => {
  /* The production-byte discipline applied to a document: the emitted
   * bytes are driven through the DOWNSTREAM validator (the offline CLI
   * signer's own closed-schema parser plus the interface's canonical
   * signing-entry assertion), not through a second in-process rebuild. */
  const built = mobileAirgap.buildSigningRequestDocument({
    request: { transaction: { unsignedSafeJson: UNSIGNED, signInputs: [{ index: 0, sighashType: 1 }] } },
    verification: PASSING_VERIFICATION,
    network: NETWORK,
    expectedSignerAddress: SIGNER
  });
  const parsed = JSON.parse(built.documentText);
  assert.deepEqual(Object.keys(parsed), [...coreAirgap.SIGNING_REQUEST_KEYS]);
  assert.deepEqual([...v2.assertCanonicalSignInputsV2(parsed.signInputs)].map((e) => ({ ...e })), [{ index: 0, sighashType: 1 }]);
  const v1 = require("../../core/signer");
  assert.deepEqual(
    [...v1.assertCanonicalSignInputs(parsed.signInputs)].map((e) => ({ ...e })),
    [{ index: 0, sighashType: 1 }],
    "the v1 core the offline CLI signer runs on must accept the document's signing entries"
  );
});

test("a response both modules accept is accepted by both", () => {
  const text = signedDocument();
  const mobileOutcome = mobileAirgap.parseSignedResponseDocument(text, {
    expectedNetwork: NETWORK,
    expectedSignerAddress: SIGNER,
    verification: PASSING_VERIFICATION
  });
  assert.equal(mobileOutcome.ok, true, mobileOutcome.detail);
  assert.equal(mobileOutcome.signedSafeJson, SIGNED);

  const coreOutcome = coreAirgap.validateSignedTransactionDocument(coreRequest(), JSON.parse(text));
  assert.deepEqual(coreOutcome, { signedSafeJson: SIGNED });
});

test("a response either module refuses is refused by BOTH — no one-sided acceptance", () => {
  const cases = [
    { name: "unknown format", override: { format: "policyvault-cli-signer-signed-transaction/2" } },
    { name: "wrong kind", override: { kind: "sign-message" } },
    { name: "wrong network", override: { network: "mainnet" } },
    { name: "wrong signer", override: { address: "kaspatest:qqsomebodyelse" } },
    { name: "empty payload", override: { signedSafeJson: "" } },
    { name: "unknown key", override: { txId: "a".repeat(64) } },
    { name: "different transaction", override: { signedSafeJson: OTHER } }
  ];
  for (const { name, override } of cases) {
    const text = signedDocument(override);
    const mobileOutcome = mobileAirgap.parseSignedResponseDocument(text, {
      expectedNetwork: NETWORK,
      expectedSignerAddress: SIGNER,
      verification: PASSING_VERIFICATION
    });
    assert.equal(mobileOutcome.ok, false, `mobile must refuse: ${name}`);
    assert.equal(typeof mobileOutcome.code, "string");

    if (name === "different transaction") {
      /* the core adapter binds transaction identity through the v2 core's
       * injected id re-derivation rather than inside the document parser,
       * so this one is proven at the interface level below */
      continue;
    }
    assert.throws(
      () => coreAirgap.validateSignedTransactionDocument(coreRequest(), JSON.parse(text)),
      (e) => typeof e.signerCode === "string",
      `the v2 adapter must refuse: ${name}`
    );
  }
});

test("the v2 adapter refuses a response for a different transaction through the interface's id re-derivation", async () => {
  const adapter = v2.createAirGapSignerAdapter({
    network: NETWORK,
    signerAddress: SIGNER,
    exchange: async () => signedDocument({ signedSafeJson: OTHER })
  });
  await adapter.connect();
  await assert.rejects(
    () => v2.executeSigningV2(adapter, coreRequest(), { timeoutMs: 60000, deriveTransactionId: (json) => JSON.parse(json).id }),
    (e) => e.signerCode === v2.SignerErrorCodesV2.PAYLOAD_MUTATED
  );
});

test("the mobile roster's qr-airgap adapter is the transport this v2 adapter declares", () => {
  const capabilities = require("../www/js/portable/signer-capabilities.js");
  const qr = capabilities.ADAPTERS.find((a) => a.id === "qr-airgap");
  assert.ok(qr, "the mobile roster still lists the QR air-gap adapter");
  const descriptor = v2.createAirGapSignerAdapter({ network: NETWORK, signerAddress: SIGNER, exchange: async () => "" }).describe();
  assert.equal(descriptor.transport, "qr-airgap");
  assert.equal(descriptor.features.airGapped, qr.features.airGapped);
  assert.equal(descriptor.features.asynchronousApproval, qr.features.asynchronousApproval);
  assert.equal(descriptor.features.specificInputSigning, qr.features.specificInputSigning);
  assert.equal(descriptor.features.accountEvents, qr.features.accountEvents);
  assert.equal(descriptor.features.multiAccount, qr.features.multiAccount);
  assert.equal(descriptor.features.networkSwitching, qr.features.networkSwitching);
  assert.equal(descriptor.features.hardwareDisplay, qr.features.hardwareDisplay);
});

test("the v2 air-gap capability limitations are carried where a mobile UI can render them", () => {
  const adapter = v2.createAirGapSignerAdapter({ network: NETWORK, signerAddress: SIGNER, exchange: async () => "" });
  assert.ok(Array.isArray(adapter.limitations) && adapter.limitations.length >= 4);
  const probe = adapter.probeCapabilities();
  assert.equal(probe.probed, false, "an offline signer is never probed optimistically");
  assert.match(probe.reason, /cannot be interrogated/);
});
