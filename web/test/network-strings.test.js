"use strict";

/*
 * Completion-standard item 5: no hardcoded "testnet-10" USER-FACING string
 * anywhere in web/*.js — the server-derived network label
 * (state.serverNetwork / ui.serverNetwork, resolved from GET /health or
 * GET /network/status) is the only source of truth for what network is
 * shown to the user. The functional gate itself (which network the app
 * REQUIRES) is untouched — it stays server-authoritative comparison logic
 * (app.js verifyNetwork(), signer-kasware-adapter.js's network validation)
 * and is explicitly exempted below, by exact line, alongside the other
 * legitimate uses of the literal string (canonical value production in
 * normalizeNetwork(), a descriptor listing BOTH supported networks, and a
 * TEST-ONLY dev-signer default whose feature is itself testnet-gated
 * server-side). web/core-bundle.js and web/verify-intent.js are F1-owned
 * (never edited by this worker) and are excluded from this worker's grep,
 * per the task boundary — not because their content is exempt in
 * principle.
 *
 * This is a grep-based regression test: it does not re-derive the reason
 * for each exemption (that reasoning lives in the source comments at each
 * site) — it pins the exact CURRENT set of exempted lines so that any
 * NEW hardcoded "testnet-10" string anywhere in these files fails the
 * test immediately, and any exemption that is removed or moved is caught
 * by the exact-set comparison (never silently stale).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");

function linesContaining(file, needle) {
  const src = fs.readFileSync(path.join(WEB_DIR, file), "utf8");
  const out = [];
  src.split("\n").forEach((line, i) => {
    if (line.includes(needle)) out.push({ n: i + 1, text: line.trim() });
  });
  return out;
}

/* Files this worker owns and edited for item 5. core-bundle.js and
 * verify-intent.js are F1-owned (never touched by this worker) and are
 * intentionally NOT in this list — see the module comment above. */
const OWNED_FILES = ["app.js", "app-v4.js", "wallet.js", "signer-kasware-adapter.js"];

/* Exact set of lines still legitimately carrying the literal
 * "testnet-10" string, keyed by file, after item 5's rewrite. Every one
 * is EITHER (a) fail-closed comparison/gating logic that must keep
 * comparing against the real canonical value the server also uses
 * (never a hardcoded ASSUMPTION about which network is required), or
 * (b) a normalizeNetwork()-style canonical-value producer, or (c) a
 * descriptor that lists BOTH supported networks symmetrically, or (d) a
 * test-only dev-signer default for a feature the server itself refuses
 * on mainnet (server/src/api.js: "POLICYVAULT_DEV_SIGNER=1 and testnet
 * only. Never on mainnet."). None of these are strings a user reads as
 * "this app only supports testnet-10" — every actual DISPLAY string
 * (note()/innerHTML/thrown-error-message shown to the user) now reads
 * from the server-derived network label. */
const EXEMPT = {
  "app.js": [
    151, // comment: "Gate R: testnet-10 or mainnet" — already dual-network
    154, // `ui.serverNetwork !== "testnet-10" && ui.serverNetwork !== "mainnet"` — fail-closed validity gate against the two canonical values; untouched per the mission ("do not change gating logic")
    1123 // comment explaining the staging-banner fallback explicitly does NOT assume testnet-10
  ],
  "app-v4.js": [
    12, // comment restating the two canonical values (dual-network)
    30, // comment quoting the literal for documentation purposes
    1780 // comment: "Gate R: testnet-10 or mainnet" — already dual-network (shifted by the W4 agent-suspend UI additions)
  ],
  "wallet.js": [
    80, // normalizeNetwork(): canonical output-value production from an arbitrary provider string
    81, // normalizeNetwork(): same
    355 // MockAdapter (test/dev-only; the dev-sign endpoint it talks to is itself server-refused on mainnet) default network parameter
  ],
  "signer-kasware-adapter.js": [
    73, // normalizeNetwork(): canonical output-value production (mirrors wallet.js)
    74, // normalizeNetwork(): same
    168, // descriptor networks: ["mainnet","testnet-10"] — lists BOTH supported networks
    409 // network validity gate against the two canonical values (mirrors app.js:154)
  ]
};

for (const file of OWNED_FILES) {
  test(`${file}: every remaining "testnet-10" occurrence is on the pinned exempt line set (no new hardcoded network string)`, () => {
    const hits = linesContaining(file, "testnet-10");
    const hitLines = hits.map((h) => h.n).sort((a, b) => a - b);
    const expected = (EXEMPT[file] || []).slice().sort((a, b) => a - b);
    assert.deepEqual(
      hitLines,
      expected,
      `${file}: "testnet-10" now appears on line(s) ${JSON.stringify(hitLines)} but the pinned exempt set is ${JSON.stringify(expected)}. ` +
        `If this is a NEW display string, use the module's networkLabel()/${"$"}{...} pattern instead of a literal. ` +
        `If this is a legitimate new exemption (fail-closed gating logic, a canonical-value producer, a dual-network descriptor), add it here WITH a reason.`
    );
  });
}

test("app.js and app-v4.js each define a networkLabel() helper deriving from the server-reported network, never a literal default of a specific network name", () => {
  for (const file of ["app.js", "app-v4.js"]) {
    const src = fs.readFileSync(path.join(WEB_DIR, file), "utf8");
    const m = src.match(/const networkLabel = \(\) => ([^;]+);/);
    assert.ok(m, `${file}: networkLabel() helper not found`);
    assert.ok(!/testnet-10|mainnet/.test(m[1]), `${file}: networkLabel()'s fallback must not name a specific network — got: ${m[1]}`);
  }
});

test("app-v4.js: the two former hardcoded-network user-facing strings (wallet-not-ready banner, wallet-changed prompts) now read networkLabel()", () => {
  const src = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
  assert.ok(/PolicyVault is configured for.*networkLabel\(\)/.test(src));
  assert.ok(/Wallet is not on.*networkLabel\(\)/.test(src));
});

test("app.js: the boot() staging banner never falls back to a hardcoded network name — reads h.networkId or a neutral placeholder", () => {
  const src = fs.readFileSync(path.join(WEB_DIR, "app.js"), "utf8");
  assert.ok(!/h\.networkId \|\| "testnet-10"/.test(src), "the old hardcoded fallback must be gone");
  assert.ok(/UNKNOWN NETWORK/.test(src), "a neutral fallback replaces it");
});
