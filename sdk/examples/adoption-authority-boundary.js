"use strict";

/*
 * PolicyVault SDK — adoption example: the authority boundary, offline.
 *
 * AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT
 * ENFORCES. SIGNERS RETAIN CUSTODY.
 *
 * This example builds real v0.4.1 covenant transactions with the SAME
 * SDK builders the application uses (`sdk/src/vault-builders-v4.js`),
 * driven through the real `silverc` compiler and the real
 * `pv_call_encoder` — the exact production byte path, offline (no Kaspa
 * node, no network call, no broadcast). It never signs with, requests, or
 * logs a real key: every key here is a throwaway test key constructed
 * in-process for this example only.
 *
 * It demonstrates three things a delegate/agent (human, script, or AI)
 * can do against a PolicyVault vault, and the one thing it cannot:
 *
 *   (a) a PERMITTED delegated spend — within the agent's per-transaction
 *       cap, within its period budget, to an allowlisted recipient —
 *       builds and finalizes to exact production bytes;
 *   (b) an OVER-AUTHORITY spend — a policy-valid AMOUNT redirected to a
 *       recipient that is NOT on the agent's allowlist — is REFUSED
 *       deterministically, before any signature is ever requested, with
 *       a closed error code (RECIPIENT_PROOF_INVALID). The attempt here
 *       mirrors exactly what a malicious holder of the legitimate
 *       delegate private key could hand-construct and submit directly to
 *       a Kaspa node: it declares the (unauthorized) recipient while
 *       reusing another recipient's real Merkle proof. PolicyVault's SDK
 *       runs the identical proof walk the covenant runs on-chain, so the
 *       refusal reflects consensus, not a policy opinion this layer
 *       could be talked out of;
 *   (c) an OWNER intervention (pause) — a different authority than the
 *       agent's, exercised with the owner's own key — builds and
 *       finalizes independently of any agent policy.
 *
 * Every amount is derived from the canonical KAS<->sompi parser
 * (`sdk/src/amounts.js` — integer sompi as BigInt/decimal-string; no
 * floating point ever touches a funds path).
 *
 * Prerequisites (same as the SDK test suite; see docs/selfhost-quickstart.md):
 *   - `~/silverscript` built (`cargo build` -> target/debug/silverc)
 *   - `tests/vm` built (`cargo build --bin pv_call_encoder`)
 *   - `~/rusty-kaspa`'s WASM SDK built (wasm/nodejs/kaspa)
 *
 * Run directly:
 *   node sdk/examples/adoption-authority-boundary.js
 *
 * Exercised by sdk/test/adoption-example.test.js
 * (`cd sdk && node --test test/adoption-example.test.js`).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { kasToSompi, sompiToKas } = require("../src/amounts");
const { buildRecipientTree, generateRecipientProof } = require("../src/recipient-merkle-v3");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const { buildV4Transaction, finalizeV4Transaction } = require("../src/vault-builders-v4");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");

const CONTRACT_VERSION = "policyvault-0.4.1";

/* Canonical-parser amount helper: KAS decimal string -> sompi decimal
 * string (never a JS number; never a float on a funds path). */
const K = (kas) => kasToSompi(kas).toString();

function makeConfig(dataRoot) {
  return loadConfig({ dataRoot: dataRoot ?? fs.mkdtempSync(path.join(os.tmpdir(), "pv-adoption-example-")) });
}

/*
 * A small, self-contained vault fixture: one owner, one agent policy, two
 * allowlisted recipients, one non-allowlisted "outsider", 2-of-3 external
 * approvers (unused by these three scenarios, but part of a realistic
 * v0.4.1 vault). All throwaway test keys.
 */
function buildFixture(config) {
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

  const owner = KEY(0x01);
  const agent = KEY(0x1e);
  const fuelKey = KEY(0x03);
  const recipientA = KEY(0x28); // allowlisted
  const recipientB = KEY(0x29); // allowlisted
  const outsider = KEY(0x2a); // NOT allowlisted — the redirection target in (b)
  const approvers = [KEY(20), KEY(21), KEY(22)];

  const recipientTree = buildRecipientTree([XO(recipientA), XO(recipientB)]);

  function policy(over = {}) {
    return {
      agentPk: XO(agent),
      maxPerSpend: K("20"), // this agent may never move more than 20 KAS in one spend
      periodBudget: K("50"), // ...or more than 50 KAS across one budget period
      periodLengthDaa: "864000", // ~1 day at 10 DAA/sec
      periodStartDaa: "541000000",
      periodSpent: "0",
      approvalThreshold: K("5"), // spends above 5 KAS need approver quorum; at/below, the agent signs alone
      agentMaxFeePerTx: K("1"),
      agentRecipientRoot: recipientTree.root,
      ...over
    };
  }
  const agents = [policy()];
  const agentTree = buildAgentTreeV4(agents);
  const template = { owner: XO(owner), vaultId: "22".repeat(32) };

  function state(over = {}) {
    return {
      protectedValue: K("1000"),
      feeReserve: K("50"),
      paused: "0",
      agentRoot: agentTree.root,
      approvers: approvers.map(XO),
      approvalM: "2",
      policyNonce: "0",
      ...over
    };
  }

  function chain({ fuel = true } = {}) {
    const ctx = {
      predecessorOutpoint: { transactionId: "42".repeat(32), index: 0 },
      predecessorValue: K("1050"), // protectedValue(1000) + feeReserve(50)
      covenantId: "41".repeat(32)
    };
    if (fuel) {
      ctx.fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: K("10"), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
    }
    return ctx;
  }

  const signCovenant = (build, key) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, key).slice(2);
  const signFuel = (build) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);

  return { KEY, XO, owner, agent, fuelKey, recipientA, recipientB, outsider, approvers, recipientTree, agents, template, state, chain, signCovenant, signFuel };
}

/*
 * (a) PERMITTED DELEGATED SPEND: 4 KAS (< 20 KAS cap, < 5 KAS approval
 * threshold, well inside the 50 KAS period budget) to recipientA, who IS
 * on the allowlist. Builds and finalizes to exact production bytes with
 * only the agent's own signature.
 */
function runPermittedSpend(config, fx) {
  const build = buildV4Transaction({
    config,
    templateInput: fx.template,
    stateInput: fx.state(),
    action: "agentSpend",
    params: {
      agentPk: fx.XO(fx.agent),
      agents: fx.agents,
      payAmountSompi: K("4"),
      recipient: fx.XO(fx.recipientA),
      recipients: [fx.XO(fx.recipientA), fx.XO(fx.recipientB)]
    },
    chain: fx.chain({ fuel: false }), // agentSpend may be reserve-funded; no separate fuel UTXO required
    changeXOnly: fx.XO(fx.owner),
    contractVersion: CONTRACT_VERSION
  });
  const finalized = finalizeV4Transaction({ build, covenantSignatureHex: fx.signCovenant(build, fx.agent) });
  return { build, finalized };
}

/*
 * (b) OVER-AUTHORITY SPEND: the SAME policy-valid amount (4 KAS), but
 * redirected to `outsider`, who is NOT on the allowlist. The attempt
 * reuses recipientA's real Merkle proof while declaring `outsider` as
 * the recipient — the same shape of transaction a malicious holder of
 * the legitimate agent key could hand-construct directly against a
 * node. Returns the thrown error (never throws itself) so the caller can
 * assert on the closed code; nothing is signed and nothing is built.
 */
function runRefusedSpend(config, fx) {
  const proofForA = generateRecipientProof(fx.recipientTree, fx.XO(fx.recipientA));
  try {
    buildV4Transaction({
      config,
      templateInput: fx.template,
      stateInput: fx.state(),
      action: "agentSpend",
      params: {
        agentPk: fx.XO(fx.agent),
        agents: fx.agents,
        payAmountSompi: K("4"),
        recipient: fx.XO(fx.outsider), // NOT allowlisted
        recipientProof: { root: fx.recipientTree.root, siblingsHex: proofForA.siblingsHex, pathBits: proofForA.pathBits }
      },
      chain: fx.chain({ fuel: false }),
      changeXOnly: fx.XO(fx.owner),
      contractVersion: CONTRACT_VERSION
    });
  } catch (err) {
    return err;
  }
  return null;
}

/*
 * (c) OWNER INTERVENTION: ownerPause, signed by the owner's own key (a
 * different authority entirely from the agent's). Owner operations pin
 * every covenant value exactly, so the network fee comes from a separate
 * ordinary fuel UTXO rather than the reserve.
 */
function runOwnerIntervention(config, fx) {
  const build = buildV4Transaction({
    config,
    templateInput: fx.template,
    stateInput: fx.state(),
    action: "ownerPause",
    params: {},
    chain: fx.chain({ fuel: true }),
    changeXOnly: fx.XO(fx.owner),
    contractVersion: CONTRACT_VERSION
  });
  const finalized = finalizeV4Transaction({
    build,
    covenantSignatureHex: fx.signCovenant(build, fx.owner),
    fuelSignatureScriptHex: fx.signFuel(build)
  });
  return { build, finalized };
}

function main() {
  const config = makeConfig();
  const fx = buildFixture(config);

  console.log("PolicyVault SDK adoption example — the authority boundary, offline\n");

  console.log("(a) permitted delegated spend (4 KAS, allowlisted recipient, agent signs alone)");
  const permitted = runPermittedSpend(config, fx);
  console.log(`    built + finalized: txId ${permitted.finalized.txId}\n`);

  console.log("(b) over-authority spend: same 4 KAS, redirected to a non-allowlisted recipient");
  const refusal = runRefusedSpend(config, fx);
  if (!refusal) {
    throw new Error("adoption example: expected the non-allowlisted-recipient spend to be refused, but it built successfully");
  }
  console.log(`    REFUSED before any signature was requested — code: ${refusal.code ?? "(none)"}`);
  console.log(`    ${refusal.message}\n`);

  console.log("(c) owner intervention: ownerPause, signed by the owner's own key");
  const paused = runOwnerIntervention(config, fx);
  console.log(`    built + finalized: txId ${paused.finalized.txId}\n`);

  console.log(`amounts shown: ${sompiToKas(K("4"))} KAS permitted / refused, ${sompiToKas(K("20"))} KAS cap, ${sompiToKas(K("50"))} KAS period budget`);
  console.log("\nAI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.");
}

if (require.main === module) {
  main();
}

module.exports = {
  CONTRACT_VERSION,
  makeConfig,
  buildFixture,
  runPermittedSpend,
  runRefusedSpend,
  runOwnerIntervention
};
