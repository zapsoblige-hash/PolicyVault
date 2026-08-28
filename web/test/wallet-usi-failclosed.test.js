"use strict";

/*
 * PostLaunchUpgradeOG completion-standard item 4 (surface 4 gap fix):
 * web/app.js's makeKasWareAdapter() used to silently fall back to
 * web/wallet.js's legacy KasWareAdapter — bypassing the Universal Signer
 * Interface's fail-closed capability/scheme/live-network/pre+post-identity
 * gates — whenever window.PolicyVaultKasWareSigner failed to load. That
 * bypass is now web/wallet.js's createSigningUnavailableAdapter(): every
 * method that could move toward a signature refuses with USI_UNAVAILABLE,
 * `detect()` still reports the real KasWare presence (so the UI never
 * lies and claims "not installed"), and app.js's makeKasWareAdapter()
 * constructs this instead of `new KasWareAdapter()`.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { WalletError, createSigningUnavailableAdapter } = require("../wallet.js");

test("WalletError.USI_UNAVAILABLE is a defined, distinct code", () => {
  assert.equal(WalletError.USI_UNAVAILABLE, "USI_UNAVAILABLE");
  const allCodes = new Set(Object.values(WalletError));
  assert.equal(allCodes.size, Object.keys(WalletError).length, "no accidental code collision");
});

/* ---------------- detect() reflects REAL presence, never lies ---------------- */

test("detect(): true when the injected window has kasware, independent of USI availability", () => {
  const adapter = createSigningUnavailableAdapter({ win: { kasware: {} } });
  assert.equal(adapter.detect(), true, "the UI must not claim the extension is missing when it is actually present");
});

test("detect(): false when the injected window has no kasware", () => {
  const adapter = createSigningUnavailableAdapter({ win: {} });
  assert.equal(adapter.detect(), false);
});

test("detect(): false when win itself is absent", () => {
  const adapter = createSigningUnavailableAdapter({ win: undefined });
  assert.equal(adapter.detect(), false);
});

/* ---------------- every signing-adjacent method fails closed ---------------- */

const REFUSING_METHODS = ["connect", "getNetwork", "getPublicKeyXOnly", "getPublicKeyRaw", "signAuthMessage", "signInputs"];

for (const name of REFUSING_METHODS) {
  test(`${name}(): refuses with USI_UNAVAILABLE and never touches window.kasware`, async () => {
    let touched = false;
    const win = {
      get kasware() {
        touched = true;
        return { requestAccounts: async () => ["addr"], getNetwork: async () => "kaspa_testnet_10", getPublicKey: async () => "02" + "ab".repeat(32), signMessage: async () => "ab".repeat(64), signPskt: async () => '{"ok":true}' };
      }
    };
    const adapter = createSigningUnavailableAdapter({ win });
    await assert.rejects(() => adapter[name](), (e) => e.walletCategory === "USI_UNAVAILABLE");
    assert.equal(touched, false, `${name} must refuse BEFORE reading win.kasware at all — no real provider call is possible through this stub`);
  });
}

test("the refusal message names the real cause (a build/deployment defect) — never blames the wallet or the user", async () => {
  const adapter = createSigningUnavailableAdapter({ win: { kasware: {} } });
  await assert.rejects(() => adapter.connect(), (e) => /Universal Signer Interface/.test(e.message) && /not a problem with your wallet/i.test(e.message));
});

/* ---------------- inert no-ops: nothing was ever connected ---------------- */

test("disconnect()/reconnect() are inert no-ops — never throw, reconnect always resolves null (nothing to restore)", async () => {
  const adapter = createSigningUnavailableAdapter({ win: { kasware: {} } });
  await assert.doesNotReject(() => adapter.disconnect());
  assert.equal(await adapter.reconnect(), null);
});

test("getActiveAddress() always returns null — no identity was ever established", () => {
  const adapter = createSigningUnavailableAdapter({ win: { kasware: {} } });
  assert.equal(adapter.getActiveAddress(), null);
});

test("getCapabilities() reports every capability as false — no caller can mistake this for a working signer", () => {
  const adapter = createSigningUnavailableAdapter({ win: { kasware: {} } });
  const caps = adapter.getCapabilities();
  assert.deepEqual(Object.values(caps), Object.values(caps).map(() => false));
});

test("on() registers no real listener and never throws (KasWare account/network events are inert here)", () => {
  const adapter = createSigningUnavailableAdapter({ win: { kasware: {} } });
  assert.doesNotThrow(() => adapter.on("account", () => { throw new Error("must never be called"); }));
});

/* ---------------- defaults to the real `window` when `win` is omitted (browser default) ---------------- */

test("with no `win` option and no global window (this Node test process), detect() fails closed to false rather than throwing", () => {
  const adapter = createSigningUnavailableAdapter({});
  assert.equal(adapter.detect(), false);
});

/* ---------------- app.js source-level integration check ----------------
 * app.js cannot be booted headlessly without a large DOM stub (it touches
 * many named elements directly); instead this proves the SOURCE no
 * longer constructs the legacy bypass in the fallback branch, and that
 * the fallback now routes through the fail-closed factory tested above —
 * the actual behavior contract this file exercises directly. */
test("web/app.js source: makeKasWareAdapter's fallback branch constructs createSigningUnavailableAdapter(), never `new KasWareAdapter()`", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  const fnMatch = src.match(/function makeKasWareAdapter\(\)\s*{[\s\S]*?\n {2}}/);
  assert.ok(fnMatch, "makeKasWareAdapter() must still exist");
  const body = fnMatch[0];
  assert.ok(body.includes("PolicyVaultWallet.createSigningUnavailableAdapter()"), "fallback must construct the fail-closed adapter");
  assert.ok(!/new\s+KasWareAdapter\s*\(/.test(body), "the legacy direct-KasWare adapter must never be constructed here");
});

test("web/app.js source: KasWareAdapter is not destructured/imported at module scope (nothing left to accidentally construct)", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  const topDestructure = src.match(/const\s*{\s*[^}]*}\s*=\s*PolicyVaultWallet;/);
  assert.ok(topDestructure, "the PolicyVaultWallet destructure must still exist");
  assert.ok(!/\bKasWareAdapter\b/.test(topDestructure[0]), "KasWareAdapter must not be pulled into app.js's local scope");
});
