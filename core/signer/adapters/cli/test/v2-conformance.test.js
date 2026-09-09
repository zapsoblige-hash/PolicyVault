"use strict";

/*
 * UNIT (REAL CRYPTOGRAPHY) — CLI keyfile signer behind Universal Signer
 * Interface v2.
 *
 * The v1 suites in this directory already prove the adapter's signing
 * behaviour. This file proves the v2 additions on the SAME adapter with
 * the SAME real kaspa-wasm cryptography (BIP-340 Schnorr in Kaspa's
 * PersonalMessageSigningHash / TransactionSigningHash domains), including
 * the one check that needs a real transaction implementation: the
 * transaction-identity re-derivation that detects a signer returning
 * different bytes.
 *
 * TEST keys only — throwaway, generated per run, testnet-10.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2,
  validateAdapterV2,
  SignerRegistryV2,
  requireCapabilitiesV2,
  negotiateCapabilitiesV2,
  POLICYVAULT_TRANSACTION_REQUIREMENTS,
  createMessageSigningRequestV2,
  createTransactionSigningRequestV2,
  executeSigningV2,
  createReplayGuard,
  normalizePublicKeyToXOnly
} = require("../../../v2");
const { createCliSignerAdapterV2, probeCliSigner, CLI_V2_DECLARATIONS } = require("../../../v2/adapters/cli");
const { generateKeyfile } = require("../adapter");
const { loadKaspaOrExplain, makeTempDir, buildUnsignedTxSafeJson } = require("../testkit");

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-cli-signer-v2-");
const keyfilePath = path.join(dir, "test-key.json");
const identity = generateKeyfile({ out: keyfilePath, network: "testnet-10", label: "v2 conformance test key", kaspaModule: kaspa });

function makeAdapter() {
  return createCliSignerAdapterV2({ keyfilePath, network: "testnet-10", kaspaModule: kaspa });
}

/* The authoritative id derivation, injected exactly as a production
 * consumer would inject it (the core deliberately holds no transaction
 * code of its own). */
function deriveTransactionId(safeJson) {
  return String(kaspa.Transaction.deserializeFromSafeJSON(safeJson).id);
}

function txRequest(unsignedSafeJson) {
  return createTransactionSigningRequestV2({
    unsignedSafeJson,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: identity.address,
    ttlMs: 60000
  });
}

test("v2 conformance: the lifted CLI adapter validates, registers, and declares the CLI profile", async () => {
  const adapter = makeAdapter();
  const { descriptor } = validateAdapterV2(adapter);
  assert.equal(descriptor.interfaceVersion, SIGNER_INTERFACE_VERSION_V2);
  assert.equal(descriptor.provider, "cli-keyfile");
  assert.equal(descriptor.kind, "cli");
  assert.equal(descriptor.transport, "cli");
  assert.equal(descriptor.userPresence, CLI_V2_DECLARATIONS.userPresence);
  assert.equal(descriptor.cancellation, "unsupported");
  assert.deepEqual({ ...descriptor.sighash }, { all: true, none: false, single: false, anyoneCanPay: false });
  assert.deepEqual([...descriptor.transactionFormats], ["kaspa-safe-json/1"]);
  assert.equal(descriptor.pskt.supported, false);

  const registry = new SignerRegistryV2();
  assert.equal(registry.register(adapter).provider, "cli-keyfile");
  assert.equal(requireCapabilitiesV2(descriptor, { ...POLICYVAULT_TRANSACTION_REQUIREMENTS }).ok, true);
});

test("v2 conformance: the probe reports the real kaspa-wasm surface this adapter drives", () => {
  const report = probeCliSigner({ kaspaModule: kaspa });
  assert.equal(report.probed, true);
  assert.ok(report.methods.includes("signMessage"));
  assert.ok(report.methods.includes("signTransaction"));
  assert.deepEqual(report.transactionFormats, ["kaspa-safe-json/1"]);
  assert.equal(report.pskt.supported, false);
});

test("v2 REAL SIGNING: a personal message is signed and the signature verifies against the signer's own key", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const message = "PolicyVault sign-in (v2 conformance). This signature only signs you in. It cannot move funds.";
  const request = createMessageSigningRequestV2({
    message,
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: identity.address,
    ttlMs: 60000
  });
  const outcome = await executeSigningV2(adapter, request, { requireProbedCapabilities: true });
  assert.equal(outcome.status, "approved");
  assert.match(outcome.result.signature, /^[0-9a-f]{128}$/);

  /* the authoritative verifier — the same call server/src/auth.js makes */
  const xOnly = normalizePublicKeyToXOnly(await adapter.getPublicKey(), "CLI signer");
  assert.equal(xOnly, identity.xOnlyPublicKey);
  assert.equal(kaspa.verifyMessage({ message, signature: outcome.result.signature, publicKey: new kaspa.PublicKey(identity.publicKey) }), true);
  await adapter.disconnect();
});

test("v2 REAL SIGNING: a frozen transaction is signed, keeps its consensus identity, and the core confirms it", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const { unsignedSafeJson, unsignedId } = buildUnsignedTxSafeJson(kaspa, identity.address);
  const outcome = await executeSigningV2(adapter, txRequest(unsignedSafeJson), { deriveTransactionId, requireProbedCapabilities: true });

  assert.equal(outcome.status, "approved");
  assert.equal(outcome.txIdVerified, true, "the injected derivation ran and agreed");
  assert.equal(outcome.transactionId, unsignedId, "Kaspa txids exclude signature scripts — signing must not move the id");

  const signed = kaspa.Transaction.deserializeFromSafeJSON(outcome.result.signedSafeJson);
  assert.equal(String(signed.id), unsignedId);
  assert.match(signed.inputs[0].signatureScript, /^[0-9a-f]+$/, "the named input carries a real signature script");
  assert.notEqual(signed.inputs[0].signatureScript, "", "the input was actually signed");
  await adapter.disconnect();
});

test("v2 REAL SIGNING: a signer returning bytes for a DIFFERENT transaction is detected by id re-derivation", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const mine = buildUnsignedTxSafeJson(kaspa, identity.address);
  const other = buildUnsignedTxSafeJson(kaspa, identity.address, { amount: 700_000_000n });
  assert.notEqual(mine.unsignedId, other.unsignedId, "the fixture transactions must genuinely differ");

  /* a cheating signer: correctly bound envelope, wrong bytes */
  const cheating = {
    ...adapter,
    signTransaction: async (request) => {
      const swapped = Object.freeze({ ...request, unsignedSafeJson: other.unsignedSafeJson });
      const envelope = await adapter.signTransaction(swapped);
      return { ...envelope, requestId: request.requestId, nonce: request.nonce, payloadSha256: request.payloadSha256 };
    }
  };
  await assert.rejects(
    () => executeSigningV2(cheating, txRequest(mine.unsignedSafeJson), { deriveTransactionId }),
    (e) => {
      assert.equal(e.signerCode, SignerErrorCodesV2.PAYLOAD_MUTATED);
      assert.equal(e.details.expectedTxId, mine.unsignedId);
      assert.equal(e.details.returnedTxId, other.unsignedId);
      return true;
    }
  );
  await adapter.disconnect();
});

test("v2 gates still hold on the real adapter: wrong network, wrong identity, expiry, single-use settlement", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);

  /* the adapter declares testnet-10 only */
  await assert.rejects(
    () =>
      executeSigningV2(
        adapter,
        createTransactionSigningRequestV2({
          unsignedSafeJson,
          signInputs: [{ index: 0, sighashType: 1 }],
          network: "mainnet",
          expectedSignerAddress: identity.address,
          ttlMs: 60000
        }),
        { deriveTransactionId }
      ),
    (e) => e.signerCode === SignerErrorCodesV2.WRONG_NETWORK
  );

  await assert.rejects(
    () =>
      executeSigningV2(
        adapter,
        createTransactionSigningRequestV2({
          unsignedSafeJson,
          signInputs: [{ index: 0, sighashType: 1 }],
          network: "testnet-10",
          expectedSignerAddress: "kaspatest:qqsomebodyelse00000000000000000000000000000000000000000000000",
          ttlMs: 60000
        }),
        { deriveTransactionId }
      ),
    (e) => e.signerCode === SignerErrorCodesV2.ACCOUNT_CHANGED
  );

  const stale = txRequest(unsignedSafeJson);
  await assert.rejects(
    () => executeSigningV2(adapter, Object.freeze({ ...stale, expiresAtMs: stale.createdAtMs + 1 }), { nowMs: stale.createdAtMs + 5000, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_EXPIRED
  );

  const guard = createReplayGuard();
  const once = txRequest(unsignedSafeJson);
  assert.equal((await executeSigningV2(adapter, once, { replayGuard: guard, deriveTransactionId })).status, "approved");
  await assert.rejects(
    () => executeSigningV2(adapter, once, { replayGuard: guard, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.DUPLICATE_SETTLEMENT
  );
  await adapter.disconnect();
});

test("v2 negotiation on the real adapter refuses what it genuinely cannot do", () => {
  const descriptor = makeAdapter().describe();
  assert.equal(negotiateCapabilitiesV2(descriptor, { userPresence: "required" }).code, SignerErrorCodesV2.USER_PRESENCE_REQUIRED);
  assert.equal(negotiateCapabilitiesV2(descriptor, { transports: ["in-page"] }).code, SignerErrorCodesV2.TRANSPORT_UNSUPPORTED);
  assert.equal(negotiateCapabilitiesV2(descriptor, { cancellation: "supported" }).code, SignerErrorCodesV2.UNSUPPORTED_CAPABILITY);
  assert.equal(negotiateCapabilitiesV2(descriptor, { features: ["accountEvents"] }).code, SignerErrorCodesV2.UNSUPPORTED_CAPABILITY);
  assert.equal(negotiateCapabilitiesV2(descriptor, { pskt: ["signer"] }).code, SignerErrorCodesV2.UNSUPPORTED_CAPABILITY);
  assert.equal(negotiateCapabilitiesV2(descriptor, { ...POLICYVAULT_TRANSACTION_REQUIREMENTS }).ok, true);
});
