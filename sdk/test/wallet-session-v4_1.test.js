"use strict";

/* H2 §21 — single authoritative browser wallet session + expected-signer
 * binding (v0.4.1). Two layers:
 *   (structural) the v0.4.1 dashboard consumes the ONE canonical global wallet
 *     session and never opens a second provider connection (§2/§3/§20/§21-A/H);
 *   (server) the connected wallet identity is BOUND to the expected signer — the
 *     role is derived + enforced server-side, never selected by the browser
 *     (§5/§10/§11/§21-B/C/D). A wrong/unrelated/mismatched wallet fails closed. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const WEB = path.join(__dirname, "..", "..", "web");
const read = (f) => fs.readFileSync(path.join(WEB, f), "utf8");

// ---------------- structural: one canonical wallet session ----------------
test("§21-A/H app-v4.js consumes the canonical session and opens NO second provider", () => {
  const src = read("app-v4.js");
  assert.ok(/window\.PolicyVaultWalletSession/.test(src), "v0.4.1 app must consume window.PolicyVaultWalletSession");
  // No independent KasWare/Mock provider connection from the v0.4.1 module.
  assert.ok(!/new\s+\w*\.?KasWareAdapter/.test(src), "v0.4.1 app must NOT construct its own KasWareAdapter");
  assert.ok(!/new\s+\w*\.?MockAdapter/.test(src), "v0.4.1 app must NOT construct its own MockAdapter");
  // No separately mutable second active identity.
  assert.ok(!/state\.adapter/.test(src), "v0.4.1 app must not cache a second signer adapter");
});

test("§21 app.js owns the single canonical session API", () => {
  const src = read("app.js");
  assert.ok(/window\.PolicyVaultWalletSession\s*=/.test(src), "app.js must expose the canonical session");
  for (const m of ["active", "subscribe", "connect", "disconnect"]) {
    assert.ok(new RegExp(`\\b${m}\\b`).test(src.split("window.PolicyVaultWalletSession")[1] || ""), `session must expose ${m}`);
  }
  assert.ok(/emitWalletChange\(\)/.test(src), "every wallet state change must notify subscribers");
});

test("§3 exactly one Connect KasWare button in the served UI", () => {
  const html = read("index.html");
  const buttons = (html.match(/<button[^>]*id="[^"]*connect-kasware"[^>]*>/g) || []);
  assert.equal(buttons.length, 1, `exactly one Connect KasWare button, found ${buttons.length}`);
  assert.equal(buttons[0].includes('id="btn-connect-kasware"'), true, "the one connect control is the global Wallet button");
  assert.ok(!/id="v4-connect-kasware"/.test(html), "the v0.4.1 second connect control must be removed");
  assert.ok(!/id="v4-connect-mock"/.test(html), "the v0.4.1 second dev-signer control must be removed");
});

// -------------- server: expected-signer binding (role derived) --------------
const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4_1 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const wr4 = require("../src/wallet-requests-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv41-session-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = 1, AGENT_A = 0x1e, AGENT_B = 0x1f, RECIP = 0x28, UNRELATED = 0x66;
const VAULT_ID = "24".repeat(32);
const agentEntry = (v) => ({ agentPk: XO(v), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(RECIP)] });

function seedV41() {
  const registry = [agentEntry(AGENT_A), agentEntry(AGENT_B)];
  const template = { owner: XO(OWNER), vaultId: VAULT_ID };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4_1, networkId: config.networkId, vaultId: VAULT_ID,
    label: "session", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "45".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
seedV41();
const fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(OWNER)}ac` };

test("§10/§21-B agent action binds the connected wallet to the acting agentPk", () => {
  // The connected wallet IS agent A -> authorized.
  const ok = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { agentPk: XO(AGENT_A), recipient: XO(RECIP), payAmountSompi: (4n * KAS).toString() }, signerAddress: ADDR(AGENT_A) });
  assert.ok(ok.requestId, "agent A spending as agent A is authorized");
  // The connected wallet is agent B but the request claims to act as agent A ->
  // the server derives the signer (B) and refuses (role is NOT a browser claim).
  assert.throws(
    () => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { agentPk: XO(AGENT_A), recipient: XO(RECIP), payAmountSompi: (4n * KAS).toString() }, signerAddress: ADDR(AGENT_B) }),
    /NOT_AGENT|AUTHORIZATION|agent/i, "agent B cannot spend as agent A"
  );
});

test("§21-D unrelated wallet gets no privileged authorization", () => {
  assert.throws(
    () => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { agentPk: XO(AGENT_A), recipient: XO(RECIP), payAmountSompi: (4n * KAS).toString() }, signerAddress: ADDR(UNRELATED) }),
    /NOT_AGENT|AUTHORIZATION|agent/i, "unrelated wallet cannot spend"
  );
  assert.throws(
    () => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerPause", params: { fuel }, signerAddress: ADDR(UNRELATED) }),
    /NOT_OWNER|AUTHORIZATION|owner/i, "unrelated wallet cannot perform owner ops"
  );
});

test("§10 owner action binds the connected wallet to the vault owner", () => {
  const ok = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerPause", params: { fuel }, signerAddress: ADDR(OWNER) });
  assert.ok(ok.requestId, "owner may pause");
  assert.throws(
    () => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerPause", params: { fuel }, signerAddress: ADDR(AGENT_A) }),
    /NOT_OWNER|AUTHORIZATION|owner/i, "an agent cannot perform owner ops"
  );
});
