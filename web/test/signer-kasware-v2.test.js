"use strict";

/*
 * BROWSER-LAYER UNIT — KasWare behind Universal Signer Interface v2.
 *
 * The load-bearing claim of this file is NEGATIVE: carrying KasWare onto
 * v2 changes NOTHING the provider sees. Every test drives a mocked
 * `window.kasware` that records each invocation, and the central case
 * compares the recorded provider calls of the v1 path and the v2 path
 * for byte-level equality.
 *
 * The shipped production signing path (createKasWareSessionAdapter ->
 * core/signer v1) is untouched and is re-asserted here as such.
 *
 * EVIDENCE LABEL: UNIT-TESTED against the documented KasWare provider
 * API. No live KasWare extension is exercised anywhere in this track —
 * nothing here is cross-wallet verified.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const core = require("../core-bundle.js");
const { createModule } = require("../signer-kasware-adapter.js");
const kasMod = createModule(core);
const ifaceV1 = core.signerInterface;
const ifaceV2 = core.signerInterfaceV2;
const CODES = core.signerErrorsV2.SignerErrorCodesV2;

const ADDRESS_A = "kaspatest:qqkaswareaccounta000000000000000000000000000000000000000000000";
const ADDRESS_B = "kaspatest:qqkaswareaccountb000000000000000000000000000000000000000000000";
const COMPRESSED = "02" + "ab".repeat(32);
const SAFE_JSON = JSON.stringify({ id: "aa".repeat(32), version: 1, inputs: [{ index: 0 }], outputs: [] });
const SIGNED_JSON = JSON.stringify({ id: "aa".repeat(32), version: 1, inputs: [{ index: 0, signatureScript: "41ff" }], outputs: [] });
const SIGN_INPUTS = [{ index: 0, sighashType: 1 }];
const MESSAGE = "PolicyVault sign-in. This signature only signs you in. It cannot move funds.";

function deriveTransactionId(safeJson) {
  return JSON.parse(safeJson).id;
}

function fakeKasware(overrides = {}) {
  const calls = [];
  const listeners = {};
  const kw = {
    calls,
    _accounts: [ADDRESS_A],
    _network: "kaspa_testnet_10", // the raw provider label KasWare reports
    requestAccounts: async () => { calls.push(["requestAccounts"]); return kw._accounts; },
    getAccounts: async () => { calls.push(["getAccounts"]); return kw._accounts; },
    getNetwork: async () => { calls.push(["getNetwork"]); return kw._network; },
    getPublicKey: async () => { calls.push(["getPublicKey"]); return COMPRESSED; },
    signMessage: async (message, opts) => { calls.push(["signMessage", message, opts]); return "AB".repeat(64); },
    signPskt: async (args) => { calls.push(["signPskt", args]); return SIGNED_JSON; },
    disconnect: async (origin) => { calls.push(["disconnect", origin]); },
    on: (event, cb) => { (listeners[event] = listeners[event] || []).push(cb); },
    _emit: (event, arg) => { (listeners[event] || []).forEach((cb) => cb(arg)); },
    ...overrides
  };
  return kw;
}

function winFor(kw) {
  return { kasware: kw, location: { origin: "http://127.0.0.1:3080" } };
}

function v2TxRequest(overrides = {}) {
  return ifaceV2.createTransactionSigningRequestV2({
    unsignedSafeJson: SAFE_JSON,
    signInputs: SIGN_INPUTS,
    network: "testnet-10",
    expectedSignerAddress: ADDRESS_A,
    ttlMs: 60000,
    ...overrides
  });
}

function v2MsgRequest(overrides = {}) {
  return ifaceV2.createMessageSigningRequestV2({
    message: MESSAGE,
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: ADDRESS_A,
    ttlMs: 60000,
    ...overrides
  });
}

/* =================== descriptor + profile =================== */

test("the v2 KasWare adapter passes validateAdapterV2 and declares the profile's exact capabilities", async () => {
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(fakeKasware()) });
  await adapter.connect();
  const { descriptor } = ifaceV2.validateAdapterV2(adapter);
  assert.deepEqual(
    {
      interfaceVersion: descriptor.interfaceVersion,
      provider: descriptor.provider,
      label: descriptor.label,
      kind: descriptor.kind,
      schemes: [...descriptor.schemes],
      networks: [...descriptor.networks],
      sighash: { ...descriptor.sighash },
      pskt: { supported: descriptor.pskt.supported, roles: [...descriptor.pskt.roles] },
      transactionFormats: [...descriptor.transactionFormats],
      userPresence: descriptor.userPresence,
      transport: descriptor.transport,
      cancellation: descriptor.cancellation
    },
    {
      interfaceVersion: "policyvault-signer/2",
      provider: "kasware",
      label: "KasWare",
      kind: "browser-extension",
      schemes: ["schnorr"],
      networks: ["mainnet", "testnet-10"],
      sighash: { all: true, none: false, single: false, anyoneCanPay: false },
      pskt: { supported: false, roles: [] },
      transactionFormats: ["kaspa-safe-json/1"],
      userPresence: "required",
      transport: "in-page",
      cancellation: "unsupported"
    }
  );
  /* the v1 half is carried over verbatim from the unchanged v1 adapter */
  const v1Descriptor = ifaceV1.validateAdapter(kasMod.createKasWareUsiAdapter({ win: winFor(fakeKasware()) })).descriptor;
  assert.deepEqual({ ...descriptor.features }, { ...v1Descriptor.features });
});

test("the v1 KasWare adapter and the shipped session adapter are UNCHANGED and still v1", () => {
  const win = winFor(fakeKasware());
  const v1Adapter = kasMod.createKasWareUsiAdapter({ win });
  assert.equal(ifaceV1.validateAdapter(v1Adapter).descriptor.interfaceVersion, "policyvault-signer/1");
  const session = kasMod.createKasWareSessionAdapter({ win });
  assert.equal(session.interfaceVersion, "policyvault-signer/1", "the shipped production path stays on v1");
  assert.equal(typeof session.signInputs, "function");
  assert.equal(typeof session.signAuthMessage, "function");
});

/* =================== byte-identical provider calls =================== */

test("PARITY: the provider invocations of the v1 and v2 paths are byte-identical (transaction)", async () => {
  const kwV1 = fakeKasware();
  const kwV2 = fakeKasware();

  const a1 = kasMod.createKasWareUsiAdapter({ win: winFor(kwV1) });
  await a1.connect();
  const v1Request = ifaceV1.createTransactionSigningRequest({
    unsignedSafeJson: SAFE_JSON,
    signInputs: SIGN_INPUTS,
    network: "testnet-10",
    expectedSignerAddress: ADDRESS_A
  });
  const v1Out = await ifaceV1.executeSigning(a1, v1Request);

  const a2 = kasMod.createKasWareUsiV2Adapter({ win: winFor(kwV2) });
  await a2.connect();
  const v2Out = await ifaceV2.executeSigningV2(a2, v2TxRequest(), { deriveTransactionId });

  const signPsktV1 = kwV1.calls.filter((c) => c[0] === "signPskt");
  const signPsktV2 = kwV2.calls.filter((c) => c[0] === "signPskt");
  assert.equal(signPsktV1.length, 1);
  assert.equal(signPsktV2.length, 1);
  assert.deepEqual(signPsktV2[0], signPsktV1[0], "the provider must receive byte-identical signPskt arguments under v2");
  assert.equal(JSON.stringify(signPsktV2[0]), JSON.stringify(signPsktV1[0]));
  assert.deepEqual(signPsktV2[0][1], { txJsonString: SAFE_JSON, options: { signInputs: [{ index: 0, sighashType: 1 }] } });

  /* the same signed bytes come back out, verbatim, on both versions */
  assert.equal(v1Out.result.signedSafeJson, SIGNED_JSON);
  assert.equal(v2Out.result.signedSafeJson, SIGNED_JSON);
  assert.equal(v2Out.txIdVerified, true, "v2 additionally re-derived the transaction identity");
});

test("PARITY: the provider invocations of the v1 and v2 paths are byte-identical (personal message)", async () => {
  const kwV1 = fakeKasware();
  const kwV2 = fakeKasware();

  const a1 = kasMod.createKasWareUsiAdapter({ win: winFor(kwV1) });
  await a1.connect();
  const v1Out = await ifaceV1.executeSigning(
    a1,
    ifaceV1.createMessageSigningRequest({ message: MESSAGE, scheme: "schnorr", network: "testnet-10", expectedSignerAddress: ADDRESS_A })
  );

  const a2 = kasMod.createKasWareUsiV2Adapter({ win: winFor(kwV2) });
  await a2.connect();
  const v2Out = await ifaceV2.executeSigningV2(a2, v2MsgRequest());

  const m1 = kwV1.calls.filter((c) => c[0] === "signMessage");
  const m2 = kwV2.calls.filter((c) => c[0] === "signMessage");
  assert.deepEqual(m2, m1, "the message and the FORCED { type: 'schnorr' } option must be identical");
  assert.deepEqual(m2[0], ["signMessage", MESSAGE, { type: "schnorr" }]);
  assert.equal(v2Out.result.signature, v1Out.result.signature);
  assert.equal(v2Out.result.signature, "ab".repeat(64), "lowercased 128-hex, same contract as v1");
});

/* =================== the probe =================== */

test("the probe observes the REAL injected surface and maps provider names to interface names", () => {
  const kw = fakeKasware();
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  const report = adapter.probeCapabilities();
  assert.equal(report.probed, true);
  assert.deepEqual([...report.methods].sort(), ["on", "signMessage", "signTransaction"]);
  assert.equal(report.pskt.supported, false, "signPskt is a Safe-JSON transaction signer, not a BIP-370 PSKT surface");
  assert.deepEqual(report.transactionFormats, ["kaspa-safe-json/1"]);
});

test("with NO provider injected the probe reports probed:false with a reason", () => {
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: { location: { origin: "http://x" } } });
  const report = adapter.probeCapabilities();
  assert.equal(report.probed, false);
  assert.match(report.reason, /no KasWare provider is injected/);
});

test("a provider WITHOUT signPskt refuses a transaction request before any prompt opens", async () => {
  const kw = fakeKasware();
  delete kw.signPskt;
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  await adapter.connect();
  await assert.rejects(
    () => ifaceV2.executeSigningV2(adapter, v2TxRequest(), { deriveTransactionId }),
    (e) => {
      assert.equal(e.signerCode, CODES.CAPABILITY_MISMATCH);
      assert.match(e.details.mismatches.join(" "), /transactionSigning declared but the provider exposes no signTransaction/);
      return true;
    }
  );
  assert.equal(kw.calls.filter((c) => c[0] === "signPskt").length, 0);
});

test("observeKasWareProvider reports only method names — never the provider object", () => {
  const kw = fakeKasware();
  const found = kasMod.observeKasWareProvider(winFor(kw));
  assert.equal(found.present, true);
  for (const name of found.methods) assert.equal(typeof name, "string");
  assert.equal(kasMod.observeKasWareProvider({}).present, false);
  assert.equal(kasMod.observeKasWareProvider(undefined).present, false);
});

/* =================== fail-closed gates on the browser adapter ========= */

test("a live network different from the request's is refused and no prompt opens", async () => {
  const kw = fakeKasware();
  kw._network = "kaspa_mainnet";
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  await adapter.connect();
  await assert.rejects(() => ifaceV2.executeSigningV2(adapter, v2TxRequest(), { deriveTransactionId }), (e) => e.signerCode === CODES.WRONG_NETWORK);
  assert.equal(kw.calls.filter((c) => c[0] === "signPskt").length, 0);
});

test("an account switch before the request is refused; a switch DURING it discards the signature", async () => {
  const kw = fakeKasware();
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  await adapter.connect();
  kw._emit("accountsChanged", [ADDRESS_B]);
  await assert.rejects(() => ifaceV2.executeSigningV2(adapter, v2TxRequest(), { deriveTransactionId }), (e) => e.signerCode === CODES.ACCOUNT_CHANGED);
  assert.equal(kw.calls.filter((c) => c[0] === "signPskt").length, 0);

  const kw2 = fakeKasware();
  kw2.signPskt = async (args) => {
    kw2.calls.push(["signPskt", args]);
    kw2._emit("accountsChanged", [ADDRESS_B]);
    return SIGNED_JSON;
  };
  const adapter2 = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw2) });
  await adapter2.connect();
  await assert.rejects(
    () => ifaceV2.executeSigningV2(adapter2, v2TxRequest(), { deriveTransactionId }),
    (e) => e.signerCode === CODES.ACCOUNT_CHANGED
  );
});

test("a provider returning bytes for a DIFFERENT transaction is caught by id re-derivation", async () => {
  const kw = fakeKasware({ signPskt: async () => JSON.stringify({ id: "bb".repeat(32), version: 1, inputs: [], outputs: [] }) });
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  await adapter.connect();
  await assert.rejects(
    () => ifaceV2.executeSigningV2(adapter, v2TxRequest(), { deriveTransactionId }),
    (e) => e.signerCode === CODES.PAYLOAD_MUTATED && e.details.returnedTxId === "bb".repeat(32)
  );
});

test("a holder rejection is classified USER_REJECTED through the v2 taxonomy", async () => {
  const rejection = Object.assign(new Error("User rejected the request"), { code: 4001 });
  const kw = fakeKasware({ signPskt: async () => { throw rejection; } });
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  await adapter.connect();
  await assert.rejects(() => ifaceV2.executeSigningV2(adapter, v2TxRequest(), { deriveTransactionId }), (e) => e.signerCode === CODES.USER_REJECTED);
});

test("a stale request is refused before the provider is contacted", async () => {
  const kw = fakeKasware();
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(kw) });
  await adapter.connect();
  const request = v2TxRequest({ ttlMs: 1000, nowMs: 1000 });
  await assert.rejects(
    () => ifaceV2.executeSigningV2(adapter, request, { nowMs: 999999999, deriveTransactionId }),
    (e) => e.signerCode === CODES.REQUEST_EXPIRED
  );
  assert.equal(kw.calls.filter((c) => c[0] === "signPskt").length, 0);
});

/* =================== honest negotiation outcomes ===================== */

test("negotiation refuses KasWare for the things it genuinely cannot do, and accepts the funds-path set", async () => {
  const adapter = kasMod.createKasWareUsiV2Adapter({ win: winFor(fakeKasware()) });
  const descriptor = adapter.describe();
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { cancellation: "supported" }).code, CODES.UNSUPPORTED_CAPABILITY);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { features: ["airGapped"] }).code, CODES.UNSUPPORTED_CAPABILITY);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { features: ["asynchronousApproval"] }).code, CODES.UNSUPPORTED_CAPABILITY);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { transports: ["qr-airgap", "file"] }).code, CODES.TRANSPORT_UNSUPPORTED);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { pskt: ["signer"] }).code, CODES.UNSUPPORTED_CAPABILITY);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { schemes: ["ecdsa"] }).code, CODES.UNSUPPORTED_SCHEME);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { userPresence: "required" }).ok, true);
  assert.equal(ifaceV2.negotiateCapabilitiesV2(descriptor, { ...ifaceV2.POLICYVAULT_TRANSACTION_REQUIREMENTS }).ok, true);
});
