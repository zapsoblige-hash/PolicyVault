"use strict";

/*
 * BROWSER-layer contract tests for the generic wallet adapter (run in Node
 * against fake providers — only the provider boundary is faked, matching
 * the directive: no funds-critical logic is mocked because none lives in
 * the adapters).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { WalletError, KasWareAdapter, MockAdapter, normalizeNetwork, normalizePublicKeyToXOnly } = require("../../web/wallet.js");
const { normalizeTemplateV2 } = require("../src/vault-state-v2");

function fakeKasware(overrides = {}) {
  return {
    requestAccounts: async () => ["kaspatest:qqfakeaccount"],
    getAccounts: async () => ["kaspatest:qqfakeaccount"],
    getNetwork: async () => "kaspa_testnet_10",
    signPskt: async ({ txJsonString }) => JSON.stringify({ ...JSON.parse(txJsonString), signed: true }),
    on: () => {},
    ...overrides
  };
}

async function withWindow(kasware, fn) {
  global.window = kasware === null ? {} : { kasware };
  try {
    return await fn();
  } finally {
    delete global.window;
  }
}

test("network normalization is canonical", () => {
  assert.equal(normalizeNetwork("kaspa_testnet_10"), "testnet-10");
  assert.equal(normalizeNetwork("testnet-10"), "testnet-10");
  assert.equal(normalizeNetwork("KASPA_MAINNET"), "mainnet");
  assert.equal(normalizeNetwork(null), null);
});

test("detection: absent provider -> detect false, calls fail WALLET_NOT_FOUND", async () => {
  await withWindow(null, async () => {
    const a = new KasWareAdapter();
    assert.equal(a.detect(), false);
    await assert.rejects(() => a.connect(), (e) => e.walletCategory === WalletError.WALLET_NOT_FOUND);
  });
});

test("connect resolves account + normalized network; capabilities exposed", async () => {
  await withWindow(fakeKasware(), async () => {
    const a = new KasWareAdapter();
    assert.equal(a.detect(), true);
    const { address, network } = await a.connect();
    assert.equal(address, "kaspatest:qqfakeaccount");
    assert.equal(network, "testnet-10");
    const caps = a.getCapabilities();
    assert.equal(caps.canSignSpecificInputs, true);
  });
});

test("user rejection maps to USER_REJECTED for connect and sign", async () => {
  const rejecting = fakeKasware({
    requestAccounts: async () => {
      throw Object.assign(new Error("User rejected the request"), { code: 4001 });
    }
  });
  await withWindow(rejecting, async () => {
    await assert.rejects(() => new KasWareAdapter().connect(), (e) => e.walletCategory === WalletError.USER_REJECTED);
  });
  const rejectSign = fakeKasware({
    signPskt: async () => {
      throw Object.assign(new Error("denied"), { code: 4001 });
    }
  });
  await withWindow(rejectSign, async () => {
    const a = new KasWareAdapter();
    await a.connect();
    await assert.rejects(() => a.signInputs("{}", [{ index: 0, sighashType: 1 }]), (e) => e.walletCategory === WalletError.USER_REJECTED);
  });
});

test("unsupported signing capability fails SIGNING_UNSUPPORTED", async () => {
  await withWindow(fakeKasware({ signPskt: undefined }), async () => {
    const a = new KasWareAdapter();
    await a.connect();
    await assert.rejects(() => a.signInputs("{}", [{ index: 0 }]), (e) => e.walletCategory === WalletError.SIGNING_UNSUPPORTED);
  });
});

test("malformed provider signature response fails INVALID_SIGNATURE_RESPONSE", async () => {
  await withWindow(fakeKasware({ signPskt: async () => "" }), async () => {
    const a = new KasWareAdapter();
    await a.connect();
    await assert.rejects(() => a.signInputs("{}", [{ index: 0 }]), (e) => e.walletCategory === WalletError.INVALID_SIGNATURE_RESPONSE);
  });
});

test("account/network change events reach subscribers", async () => {
  const handlers = {};
  const provider = fakeKasware({ on: (ev, cb) => (handlers[ev] = cb) });
  await withWindow(provider, async () => {
    const a = new KasWareAdapter();
    await a.connect();
    let acct = null;
    let net = null;
    a.on("account", (v) => (acct = v));
    a.on("network", (v) => (net = v));
    handlers.accountsChanged(["kaspatest:qqother"]);
    handlers.networkChanged("kaspa_mainnet");
    assert.equal(acct, "kaspatest:qqother");
    assert.equal(net, "mainnet");
    assert.equal(a.getActiveAddress(), "kaspatest:qqother");
  });
});

test("reconnect restores an authorized session, none otherwise", async () => {
  await withWindow(fakeKasware(), async () => {
    const a = new KasWareAdapter();
    const restored = await a.reconnect();
    assert.equal(restored.address, "kaspatest:qqfakeaccount");
  });
  await withWindow(fakeKasware({ getAccounts: async () => [] }), async () => {
    const a = new KasWareAdapter();
    assert.equal(await a.reconnect(), null);
  });
});

test("mock adapter implements the identical generic surface", () => {
  const m = new MockAdapter({ apiBase: "/api/v1" });
  for (const method of ["detect", "connect", "disconnect", "reconnect", "getActiveAddress", "getNetwork", "getCapabilities", "getPublicKeyXOnly", "signInputs", "on"]) {
    assert.equal(typeof m[method], "function", `MockAdapter must implement ${method}`);
  }
  const k = new KasWareAdapter();
  for (const method of ["detect", "connect", "disconnect", "reconnect", "getActiveAddress", "getNetwork", "getCapabilities", "getPublicKeyXOnly", "signInputs", "on"]) {
    assert.equal(typeof k[method], "function", `KasWareAdapter must implement ${method}`);
  }
});

/* ---- shared provider-pubkey normalization (owner-identity boundary) ---- */

const X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f"; // KasWare vendor-doc example key, x-only part

test("pubkey normalization: 02-compressed -> x-only", () => {
  assert.equal(normalizePublicKeyToXOnly(`02${X}`), X);
});

test("pubkey normalization: 03-compressed -> x-only", () => {
  assert.equal(normalizePublicKeyToXOnly(`03${X}`), X);
});

test("pubkey normalization: existing 64-hex x-only unchanged", () => {
  assert.equal(normalizePublicKeyToXOnly(X), X);
});

test("pubkey normalization: uppercase canonicalized to lowercase (matches SDK normalizeHex rule)", () => {
  assert.equal(normalizePublicKeyToXOnly(X.toUpperCase()), X);
  assert.equal(normalizePublicKeyToXOnly(`03${X}`.toUpperCase()), X);
  assert.equal(normalizePublicKeyToXOnly(`  ${X}  `), X); // trim, same rule
});

test("pubkey normalization: malformed lengths reject fail-closed", () => {
  const isInvalid = (e) => e.walletCategory === WalletError.INVALID_PUBLIC_KEY;
  assert.throws(() => normalizePublicKeyToXOnly(X.slice(0, 62)), isInvalid); // 62
  assert.throws(() => normalizePublicKeyToXOnly(X.slice(0, 63)), isInvalid); // 63 (odd)
  assert.throws(() => normalizePublicKeyToXOnly(X + "ab"), isInvalid); // 66 without 02/03 prefix... covered below too
  assert.throws(() => normalizePublicKeyToXOnly(`02${X}ab`), isInvalid); // 68
  assert.throws(() => normalizePublicKeyToXOnly(`04${X}${X}`), isInvalid); // uncompressed 65-byte
  assert.throws(() => normalizePublicKeyToXOnly(`01${X}`), isInvalid); // unsupported prefix
});

test("pubkey normalization: non-hex / missing / malformed provider values reject fail-closed", () => {
  const isInvalid = (e) => e.walletCategory === WalletError.INVALID_PUBLIC_KEY;
  assert.throws(() => normalizePublicKeyToXOnly("zz" + X.slice(2)), isInvalid);
  assert.throws(() => normalizePublicKeyToXOnly(""), isInvalid);
  assert.throws(() => normalizePublicKeyToXOnly("   "), isInvalid);
  assert.throws(() => normalizePublicKeyToXOnly(null), isInvalid);
  assert.throws(() => normalizePublicKeyToXOnly(undefined), isInvalid);
  assert.throws(() => normalizePublicKeyToXOnly(42), isInvalid);
  assert.throws(() => normalizePublicKeyToXOnly({ hex: X }), isInvalid);
});

test("KasWare adapter: compressed getPublicKey -> canonical x-only at the boundary", async () => {
  await withWindow(fakeKasware({ getPublicKey: async () => `03${X}` }), async () => {
    const a = new KasWareAdapter();
    await a.connect();
    assert.equal(await a.getPublicKeyXOnly(), X);
  });
  await withWindow(fakeKasware({ getPublicKey: async () => `02${X.toUpperCase()}` }), async () => {
    assert.equal(await new KasWareAdapter().getPublicKeyXOnly(), X);
  });
  await withWindow(fakeKasware({ getPublicKey: async () => X }), async () => {
    assert.equal(await new KasWareAdapter().getPublicKeyXOnly(), X); // already x-only: unchanged
  });
});

test("KasWare adapter: missing/malformed getPublicKey fails closed", async () => {
  await withWindow(fakeKasware(), async () => {
    // fake provider has no getPublicKey at all
    await assert.rejects(() => new KasWareAdapter().getPublicKeyXOnly(), (e) => e.walletCategory === WalletError.INVALID_PUBLIC_KEY);
  });
  await withWindow(fakeKasware({ getPublicKey: async () => "" }), async () => {
    await assert.rejects(() => new KasWareAdapter().getPublicKeyXOnly(), (e) => e.walletCategory === WalletError.INVALID_PUBLIC_KEY);
  });
  await withWindow(fakeKasware({ getPublicKey: async () => ({ key: X }) }), async () => {
    await assert.rejects(() => new KasWareAdapter().getPublicKeyXOnly(), (e) => e.walletCategory === WalletError.INVALID_PUBLIC_KEY);
  });
  await withWindow(fakeKasware({ getPublicKey: async () => { throw new Error("provider exploded"); } }), async () => {
    await assert.rejects(() => new KasWareAdapter().getPublicKeyXOnly(), (e) => e.walletCategory === WalletError.PROVIDER_ERROR);
  });
});

test("mock adapter: getPublicKeyXOnly serves the dev account key; disconnected fails closed", async () => {
  const m = new MockAdapter({ apiBase: "/api/v1" });
  await assert.rejects(() => m.getPublicKeyXOnly(), (e) => e.walletCategory === WalletError.WALLET_DISCONNECTED);
  const realFetch = global.fetch;
  global.fetch = async () => ({ ok: true, json: async () => ({ accounts: [{ role: "owner", address: "kaspatest:qqmock", xonly: X }] }) });
  try {
    await m.connect();
    assert.equal(await m.getPublicKeyXOnly(), X);
  } finally {
    global.fetch = realFetch;
  }
});

/*
 * BROWSER/create regression (manual real-KasWare defect 2026-08-16): a
 * real-wallet-style compressed owner pubkey, flowing exactly as the
 * dashboard flows it (adapter.getPublicKeyXOnly() -> templateInput.owner),
 * must reach the v0.2 template validator as canonical x-only and must NOT
 * reproduce "template.owner must be 32-byte lowercase hex".
 */
test("BROWSER regression: compressed wallet owner key passes template validation as x-only", async () => {
  await withWindow(fakeKasware({ getPublicKey: async () => `03${X}` }), async () => {
    const a = new KasWareAdapter();
    await a.connect();
    const owner = await a.getPublicKeyXOnly(); // exactly what app.js submits
    const vaultId = "11".repeat(32);
    const template = normalizeTemplateV2({ owner, vaultId }); // the validator that threw
    assert.equal(template.owner, X);
  });
});

test("BROWSER regression: template validation itself stays strict (raw compressed owner still rejected)", () => {
  assert.throws(
    () => normalizeTemplateV2({ owner: `03${X}`, vaultId: "11".repeat(32) }),
    /template\.owner must be 32-byte lowercase hex/
  );
});
