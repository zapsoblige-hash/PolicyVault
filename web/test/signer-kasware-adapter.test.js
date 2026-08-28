"use strict";

/*
 * KasWare behind the Universal Signer Interface — conformance, byte-level
 * flow equivalence with the legacy web/wallet.js KasWareAdapter, error
 * taxonomy mapping, and the fail-closed identity/network gates. Driven
 * against a mocked window.kasware provider that records every invocation.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const core = require("../core-bundle.js");
const { createModule } = require("../signer-kasware-adapter.js");
const kasMod = createModule(core);
const iface = core.signerInterface;

const ADDRESS_A = "kaspatest:qqkaswareaccounta000000000000000000000000000000000000000000000";
const ADDRESS_B = "kaspatest:qqkaswareaccountb000000000000000000000000000000000000000000000";
const COMPRESSED = "02" + "ab".repeat(32);
const SAFE_JSON = JSON.stringify({ id: "aa".repeat(32), version: 1, inputs: [], outputs: [] });
const SIGN_INPUTS = [{ index: 0, sighashType: 1 }];

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
    signPskt: async (args) => { calls.push(["signPskt", args]); return '{"signedSafeJson":true}'; },
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

/* run a function with a temporary GLOBAL window (for the legacy adapter,
 * which reads the window global directly) */
async function withGlobalWindow(win, fn) {
  const had = Object.prototype.hasOwnProperty.call(globalThis, "window");
  const prev = globalThis.window;
  globalThis.window = win;
  try {
    return await fn();
  } finally {
    if (had) globalThis.window = prev;
    else delete globalThis.window;
  }
}

/* =================== conformance =================== */

test("USI adapter passes core/signer validateAdapter and declares the mapped descriptor", () => {
  const usi = kasMod.createKasWareUsiAdapter({ win: winFor(fakeKasware()) });
  const { descriptor } = iface.validateAdapter(usi);
  assert.deepEqual(descriptor, {
    interfaceVersion: "policyvault-signer/1",
    provider: "kasware",
    label: "KasWare",
    kind: "browser-extension",
    schemes: ["schnorr"],
    networks: ["mainnet", "testnet-10"],
    features: {
      messageSigning: true,
      transactionSigning: true,
      specificInputSigning: true,
      multiAccount: false,
      networkSwitching: false,
      accountEvents: true,
      asynchronousApproval: false,
      airGapped: false,
      hardwareDisplay: false
    }
  });
});

test("USI adapter registers in a SignerRegistry and negotiates schnorr/testnet-10", () => {
  const usi = kasMod.createKasWareUsiAdapter({ win: winFor(fakeKasware()) });
  const registry = new iface.SignerRegistry();
  const descriptor = registry.register(usi);
  const result = iface.negotiateCapabilities(descriptor, {
    schemes: ["schnorr"],
    features: ["transactionSigning", "specificInputSigning", "messageSigning"],
    network: "testnet-10"
  });
  assert.deepEqual(result, { ok: true, provider: "kasware" });
  // and an ecdsa-only requirement structurally refuses
  const refused = iface.negotiateCapabilities(descriptor, { schemes: ["ecdsa"] });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, "UNSUPPORTED_SCHEME");
});

/* ============ flow equivalence vs the legacy adapter ============ */

test("sign-in flow equivalence: identical provider invocation bytes and identical signature result", async () => {
  const message = "PolicyVault sign-in\n\nline2\nThis signature only signs you in. It cannot move funds.";

  // legacy path (web/wallet.js KasWareAdapter reads the global window)
  const kwLegacy = fakeKasware();
  const legacyResult = await withGlobalWindow(winFor(kwLegacy), async () => {
    const { KasWareAdapter } = require("../wallet.js");
    const legacy = new KasWareAdapter();
    await legacy.connect();
    return legacy.signAuthMessage(message);
  });

  // USI path
  const kwUsi = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kwUsi) });
  await sess.connect();
  const usiResult = await sess.signAuthMessage(message, { expectedSignerAddress: ADDRESS_A, network: "testnet-10" });

  const legacyCall = kwLegacy.calls.find((c) => c[0] === "signMessage");
  const usiCall = kwUsi.calls.find((c) => c[0] === "signMessage");
  assert.deepEqual(usiCall, legacyCall, "identical provider arguments (message + forced schnorr type)");
  assert.equal(JSON.stringify(usiCall[1]), JSON.stringify(message), "challenge bytes identical");
  assert.deepEqual(usiCall[2], { type: "schnorr" }, "scheme forced explicitly, never auto");
  assert.equal(usiResult, legacyResult, "identical (lowercased 128-hex) signature result");
  assert.equal(usiResult, "ab".repeat(64));
});

test("transaction signing equivalence: identical signPskt invocation (frozen Safe JSON + canonical signInputs verbatim)", async () => {
  const kwLegacy = fakeKasware();
  const legacyResult = await withGlobalWindow(winFor(kwLegacy), async () => {
    const { KasWareAdapter } = require("../wallet.js");
    const legacy = new KasWareAdapter();
    await legacy.connect();
    return legacy.signInputs(SAFE_JSON, SIGN_INPUTS);
  });

  const kwUsi = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kwUsi) });
  await sess.connect();
  const usiResult = await sess.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_A });

  const legacyCall = kwLegacy.calls.find((c) => c[0] === "signPskt");
  const usiCall = kwUsi.calls.find((c) => c[0] === "signPskt");
  assert.equal(usiCall[1].txJsonString, legacyCall[1].txJsonString, "the EXACT frozen Safe JSON string reaches the provider");
  assert.equal(JSON.stringify(usiCall[1].options), JSON.stringify(legacyCall[1].options), "canonical signInputs byte-identical");
  assert.equal(usiResult, legacyResult, "signed Safe JSON returned verbatim");
});

test("public-key normalization parity: compressed 02/03 -> x-only; uncompressed 04 refused (both paths)", async () => {
  const kwUsi = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kwUsi) });
  assert.equal(await sess.getPublicKeyXOnly(), "ab".repeat(32));
  assert.equal(await sess.getPublicKeyRaw(), COMPRESSED);

  const kwBad = fakeKasware({ getPublicKey: async () => "04" + "cd".repeat(64) });
  const sessBad = kasMod.createKasWareSessionAdapter({ win: winFor(kwBad) });
  await assert.rejects(() => sessBad.getPublicKeyXOnly(), (e) => e.walletCategory === "INVALID_PUBLIC_KEY" && e.signerCode === "INVALID_PUBLIC_KEY");

  const legacyXOnly = await withGlobalWindow(winFor(fakeKasware()), async () => {
    const { KasWareAdapter } = require("../wallet.js");
    return new KasWareAdapter().getPublicKeyXOnly();
  });
  assert.equal(legacyXOnly, "ab".repeat(32), "parity with the legacy normalization");
});

test("connect / reconnect / disconnect parity (incl. origin-scoped disconnect)", async () => {
  const kw = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  assert.equal(sess.detect(), true);
  const c = await sess.connect();
  assert.deepEqual(c, { address: ADDRESS_A, network: "testnet-10" });
  assert.equal(sess.getActiveAddress(), ADDRESS_A);
  await sess.disconnect();
  assert.equal(sess.getActiveAddress(), null);
  const d = kw.calls.find((x) => x[0] === "disconnect");
  assert.equal(d[1], "http://127.0.0.1:3080", "origin-scoped disconnect preserved");
  const r = await sess.reconnect();
  assert.deepEqual(r, { address: ADDRESS_A, network: "testnet-10" });
  assert.equal(sess.getActiveAddress(), ADDRESS_A);
});

test("legacy capability surface preserved for existing consumers", () => {
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(fakeKasware()) });
  assert.deepEqual(sess.getCapabilities(), {
    canSignTransaction: true,
    canSignSpecificInputs: true,
    canReturnRawSignedTx: true,
    canSwitchNetwork: false,
    canExposeXOnlyPubkey: true,
    supportsAccountChangeEvents: true
  });
  assert.equal(sess.provider, "kasware");
  assert.equal(sess.label, "KasWare");
});

/* =================== fail-closed gates =================== */

test("WRONG-NETWORK fail-close: a signing request bound to testnet-10 refuses when the live wallet is on mainnet — no provider call", async () => {
  const kw = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  kw._network = "kaspa_mainnet"; // the wallet switched after connect
  await assert.rejects(
    () => sess.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_A }),
    (e) => e.signerCode === "WRONG_NETWORK" && e.walletCategory === "WRONG_NETWORK"
  );
  assert.equal(kw.calls.filter((c) => c[0] === "signPskt").length, 0, "the wallet prompt is never opened on the wrong network");
});

test("pre-invocation identity gate: a different expected signer refuses without any provider call", async () => {
  const kw = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  await assert.rejects(
    () => sess.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_B }),
    (e) => e.signerCode === "ACCOUNT_CHANGED" && e.walletCategory === "ACCOUNT_CHANGED"
  );
  assert.equal(kw.calls.filter((c) => c[0] === "signPskt").length, 0);
});

test("ACCOUNT-SWITCH fail-close: an account switch DURING signing discards the signature (post-approval re-check)", async () => {
  const kw = fakeKasware();
  kw.signPskt = async (args) => {
    kw.calls.push(["signPskt", args]);
    kw._accounts = [ADDRESS_B];
    kw._emit("accountsChanged", [ADDRESS_B]); // switch mid-popup
    return '{"signedSafeJson":true}';
  };
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  await assert.rejects(
    () => sess.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_A }),
    (e) => e.signerCode === "ACCOUNT_CHANGED"
  );
});

test("sign-in account-switch fail-close mirrors the transaction path", async () => {
  const kw = fakeKasware();
  kw.signMessage = async (message, opts) => {
    kw.calls.push(["signMessage", message, opts]);
    kw._accounts = [ADDRESS_B];
    kw._emit("accountsChanged", [ADDRESS_B]);
    return "ab".repeat(64);
  };
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  await assert.rejects(
    () => sess.signAuthMessage("challenge", { expectedSignerAddress: ADDRESS_A, network: "testnet-10" }),
    (e) => e.signerCode === "ACCOUNT_CHANGED"
  );
});

/* =================== error taxonomy =================== */

test("user rejection surfaces USER_REJECTED on both walletCategory and signerCode", async () => {
  const kw = fakeKasware({ signPskt: async () => { throw Object.assign(new Error("User rejected the request"), { code: 4001 }); } });
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  await assert.rejects(
    () => sess.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_A }),
    (e) => e.walletCategory === "USER_REJECTED" && e.signerCode === "USER_REJECTED" && e.code === "USER_REJECTED"
  );
});

test("connection rejection surfaces USER_REJECTED (legacy category preserved)", async () => {
  const kw = fakeKasware({ requestAccounts: async () => { throw Object.assign(new Error("rejected"), { code: 4001 }); } });
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await assert.rejects(() => sess.connect(), (e) => e.walletCategory === "USER_REJECTED");
});

test("missing provider methods surface SIGNING_UNSUPPORTED / UNSUPPORTED_CAPABILITY", async () => {
  const kw = fakeKasware();
  delete kw.signPskt;
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  await assert.rejects(
    () => sess.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_A }),
    (e) => e.signerCode === "UNSUPPORTED_CAPABILITY" && e.walletCategory === "SIGNING_UNSUPPORTED"
  );
});

test("empty / malformed provider results surface INVALID_SIGNATURE_RESPONSE (taxonomy refinement over legacy PROVIDER_ERROR)", async () => {
  const kwEmpty = fakeKasware({ signPskt: async () => "   " });
  const sessEmpty = kasMod.createKasWareSessionAdapter({ win: winFor(kwEmpty) });
  await sessEmpty.connect();
  await assert.rejects(
    () => sessEmpty.signInputs(SAFE_JSON, SIGN_INPUTS, { network: "testnet-10", expectedSignerAddress: ADDRESS_A }),
    (e) => e.signerCode === "INVALID_SIGNATURE_RESPONSE"
  );

  const kwBadSig = fakeKasware({ signMessage: async () => "zz".repeat(64) });
  const sessBadSig = kasMod.createKasWareSessionAdapter({ win: winFor(kwBadSig) });
  await sessBadSig.connect();
  await assert.rejects(
    () => sessBadSig.signAuthMessage("challenge", { expectedSignerAddress: ADDRESS_A }),
    (e) => e.signerCode === "INVALID_SIGNATURE_RESPONSE" && e.walletCategory === "INVALID_SIGNATURE_RESPONSE"
  );
  // documented delta: the legacy path classified this PROVIDER_ERROR; the
  // interface taxonomy names the failure precisely without losing the
  // legacy branch (walletCategory still present for existing handlers).
});

test("extension not installed surfaces WALLET_NOT_FOUND", async () => {
  const sess = kasMod.createKasWareSessionAdapter({ win: { location: { origin: "http://x" } } });
  assert.equal(sess.detect(), false);
  await assert.rejects(() => sess.connect(), (e) => e.walletCategory === "WALLET_NOT_FOUND" && e.signerCode === "SIGNER_NOT_FOUND");
});

test("account/network events propagate through the legacy event names", async () => {
  const kw = fakeKasware();
  const sess = kasMod.createKasWareSessionAdapter({ win: winFor(kw) });
  await sess.connect();
  const seen = { account: [], network: [] };
  sess.on("account", (a) => seen.account.push(a));
  sess.on("network", (n) => seen.network.push(n));
  kw._emit("accountsChanged", [ADDRESS_B]);
  kw._emit("networkChanged", "kaspa_mainnet");
  assert.deepEqual(seen.account, [ADDRESS_B]);
  assert.deepEqual(seen.network, ["mainnet"], "provider labels normalized exactly like the legacy adapter");
  assert.equal(sess.getActiveAddress(), ADDRESS_B, "tracked identity mirror follows events");
});
