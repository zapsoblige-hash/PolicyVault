"use strict";

/*
 * BROWSER — address-based create-vault identity flow (web/identity.js).
 * Only the HTTP hop is faked: the stubbed fetch routes
 * /identity/resolve-address through the REAL shared resolver, so every
 * accept/reject decision below is made by the production parser. Proves
 * the normal Create Vault workflow never requires a raw pubkey.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const { loadKaspa } = require("../src/chain");
const { resolveAddressIdentity } = require("../src/address-identity");
const { normalizeTemplateV2, normalizeStateV2 } = require("../src/vault-state-v2");
const PolicyVaultIdentity = require("../../web/identity.js");

const config = loadConfig();
const kaspa = loadKaspa(config);
const API = "/api/v1";

/* Known-valid secp256k1 X coordinates (KasWare-doc example key; G; 2G). */
const OWNER_X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const DELEGATE_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECIP_X = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const addrOf = (x) => new kaspa.XOnlyPublicKey(x).toAddress(config.networkId).toString();
const OWNER_ADDR = addrOf(OWNER_X);
const DELEGATE_ADDR = addrOf(DELEGATE_X);
const RECIP_ADDR = addrOf(RECIP_X);

/* Fake adapter: connected owner wallet. The user never types a pubkey. */
function fakeAdapter({ address = OWNER_ADDR, xonly = OWNER_X } = {}) {
  return { getActiveAddress: () => address, getPublicKeyXOnly: async () => xonly };
}

/* Stub fetch: real resolver behind the endpoint; records every URL hit. */
async function withRealResolverFetch(fn) {
  const calls = [];
  const realFetch = global.fetch;
  global.fetch = async (url, opts) => {
    calls.push(String(url));
    if (String(url).endsWith("/identity/resolve-address")) {
      const { address } = JSON.parse(opts.body);
      try {
        const identity = resolveAddressIdentity(config, address);
        return { ok: true, status: 200, json: async () => ({ identity, expectedNetwork: config.networkId }) };
      } catch (e) {
        return { ok: false, status: e.status || 422, json: async () => ({ error: { code: e.code, message: e.message } }) };
      }
    }
    throw new Error(`unexpected fetch in identity flow: ${url}`);
  };
  try {
    return await fn(calls);
  } finally {
    global.fetch = realFetch;
  }
}

test("connected owner wallet: address in, correct x-only owner out — nothing typed", async () => {
  await withRealResolverFetch(async () => {
    const ids = await PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
      delegateAddress: DELEGATE_ADDR,
      recipientAddresses: [RECIP_ADDR, "", ""]
    });
    assert.equal(ids.owner.address, OWNER_ADDR);
    assert.equal(ids.owner.xOnlyPubkey, OWNER_X);
    assert.equal(ids.delegate.xOnlyPubkey, DELEGATE_X);
    assert.deepEqual(ids.recipients.map((r) => r.xOnlyPubkey), [RECIP_X]);
  });
});

test("resolved identities pass the UNCHANGED strict template/state validation", async () => {
  await withRealResolverFetch(async () => {
    const ids = await PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
      delegateAddress: DELEGATE_ADDR,
      recipientAddresses: [RECIP_ADDR]
    });
    const template = normalizeTemplateV2({ owner: ids.owner.xOnlyPubkey, vaultId: "11".repeat(32) });
    assert.equal(template.owner, OWNER_X);
    const state = normalizeStateV2({
      protectedValue: "100000000000", periodStartDaa: "1000", periodSpent: "0", paused: "0",
      delegate: ids.delegate.xOnlyPubkey, maxPerSpend: "10000000000", periodBudget: "50000000000",
      periodLengthDaa: "600", recipients: ids.recipients.map((r) => r.xOnlyPubkey),
      delegateActive: "1", policyNonce: "0"
    });
    assert.equal(state.delegate, DELEGATE_X);
    assert.equal(state.recipients[0], RECIP_X);
  });
});

test("bad delegate address blocks the flow BEFORE any create/build request", async () => {
  await withRealResolverFetch(async (calls) => {
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
        delegateAddress: "kaspatest:qqnotanaddress",
        recipientAddresses: [RECIP_ADDR]
      }),
      (e) => e.identityCode === "ADDRESS_INVALID" && /Delegate wallet address/.test(e.message)
    );
    assert.ok(calls.every((u) => u.endsWith("/identity/resolve-address")), "no other endpoint may be hit");
  });
});

test("wrong-network delegate address blocked with a clear user-facing error", async () => {
  const mainnetAddr = new kaspa.XOnlyPublicKey(DELEGATE_X).toAddress("mainnet").toString();
  await withRealResolverFetch(async () => {
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
        delegateAddress: mainnetAddr,
        recipientAddresses: [RECIP_ADDR]
      }),
      (e) => e.identityCode === "ADDRESS_WRONG_NETWORK" && /current network/.test(e.message)
    );
  });
});

test("unsupported address types (ECDSA / ScriptHash) blocked fail-closed", async () => {
  const ecdsa = new kaspa.PublicKey(`02${DELEGATE_X}`).toAddressECDSA(config.networkId).toString();
  const p2sh = kaspa.addressFromScriptPublicKey(kaspa.payToScriptHashScript("51"), config.networkId).toString();
  await withRealResolverFetch(async () => {
    for (const bad of [ecdsa, p2sh]) {
      await assert.rejects(
        () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
          delegateAddress: bad,
          recipientAddresses: [RECIP_ADDR]
        }),
        (e) => e.identityCode === "ADDRESS_TYPE_UNSUPPORTED" && /Schnorr public-key address/.test(e.message)
      );
    }
  });
});

test("per-recipient slots: bad address in any slot blocks with the slot named", async () => {
  await withRealResolverFetch(async () => {
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
        delegateAddress: DELEGATE_ADDR,
        recipientAddresses: [RECIP_ADDR, "kaspatest:qqbroken", ""]
      }),
      (e) => /Allowed recipient 2/.test(e.message)
    );
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
        delegateAddress: DELEGATE_ADDR,
        recipientAddresses: ["", "", ""]
      }),
      (e) => e.identityCode === "RECIPIENTS_REQUIRED"
    );
  });
});

test("owner wallet/pubkey mismatch fails closed (account-switch race)", async () => {
  await withRealResolverFetch(async () => {
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter({ xonly: DELEGATE_X }), {
        delegateAddress: DELEGATE_ADDR,
        recipientAddresses: [RECIP_ADDR]
      }),
      (e) => e.identityCode === "OWNER_MISMATCH"
    );
  });
});

test("disconnected wallet fails closed before any network call", async () => {
  await withRealResolverFetch(async (calls) => {
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, { getActiveAddress: () => null, getPublicKeyXOnly: async () => OWNER_X }, {
        delegateAddress: DELEGATE_ADDR,
        recipientAddresses: [RECIP_ADDR]
      }),
      (e) => e.identityCode === "OWNER_DISCONNECTED"
    );
    assert.equal(calls.length, 0);
  });
});

test("no raw-pubkey entry works in the normal workflow: a pasted pubkey is rejected as an address", async () => {
  await withRealResolverFetch(async () => {
    await assert.rejects(
      () => PolicyVaultIdentity.resolveCreateIdentities(API, fakeAdapter(), {
        delegateAddress: DELEGATE_X, // raw 64-hex pubkey where an address belongs
        recipientAddresses: [RECIP_ADDR]
      }),
      (e) => e.identityCode === "ADDRESS_INVALID" && /Kaspa wallet address/.test(e.message)
    );
  });
});
