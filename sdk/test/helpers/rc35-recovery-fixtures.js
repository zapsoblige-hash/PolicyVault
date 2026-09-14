"use strict";
/*
 * Shared fixtures for the RC35 recovery / reservation regressions (independent RC35 affected review, 2026-09-11; owner
 * repair directive of the same day): the EXACT node answer strings from the retained rusty-kaspa source
 * (mining/errors/src/mempool.rs at cfafeb4c… — RejectAlreadyAccepted / RejectDuplicate / RejectNonStandard), wrapped the
 * way rpc/service/src/service.rs wraps every submit error (RpcError::RejectedTransaction "Rejected transaction {id}: …");
 * a scripted mock node; and a writer that persists a request EXACTLY as the PRE-CORRECTION runtime persisted a
 * rejection it had classified from the node's answer alone (state SUBMISSION_REJECTED, the answer in `error`, no proof,
 * the submission claim released) — the reviewer's false negative. TEST KEYS ONLY; nothing leaves the process.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { loadConfig } = require("../../src/config");
const { ENCODER_PATH } = require("../../src/vault-builders-v4");
const { Categories } = require("../../src/store");
const assets = require("../../../core/assets");
const { compileKcc20Program } = require("../../src/token-program-kcc20");
const { buildRecipientTree } = require("../../src/recipient-merkle-v3");

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

function toolchainSkip(prefix = "pv-rc35-probe-") {
  const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), prefix)) });
  const ok = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
  return ok ? undefined : "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
}

/* a MAINNET-LABELLED test config (mock node; nothing leaves the process) — the creation kill switch is a mainnet gate */
function mainnetConfig(over = {}) {
  const saved = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  try {
    return loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", ...over });
  } finally {
    if (saved === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = saved;
  }
}

function tokenFixture(cfg) {
  const ref = compileKcc20Program({ config: cfg, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "Recovery Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  return { descriptor };
}
function tokenPolicyFor(Hh, agentKey, recipientKey) {
  const rec = Hh.XO(recipientKey);
  return { agentPk: Hh.XO(agentKey), tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: KAS.toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: buildRecipientTree([rec]).root, recipients: [rec] };
}
function hdLeafFor(Hh, agentKey, recipientKey) {
  return { pk: Hh.XO(agentKey), maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: KAS.toString(), maxCarryKas: KAS.toString(), expiryDaa: "999999999", recipients: [Hh.XO(recipientKey)] };
}

/* EXACT node answers (rusty-kaspa mining/errors/src/mempool.rs), wrapped as rpc/core/src/error.rs RejectedTransaction */
const answers = {
  alreadyAccepted: (txId) => `Rejected transaction ${txId}: transaction ${txId} was already accepted by the consensus`,
  alreadyInMempool: (txId) => `Rejected transaction ${txId}: transaction ${txId} is already in the mempool`,
  alreadyInOrphanPool: (txId) => `Rejected transaction ${txId}: orphan transaction ${txId} is already in the orphan pool`,
  nonStandard: (txId) => `Rejected transaction ${txId}: transaction ${txId} is not standard: transaction input #0 has 18 signature operations which is more than the allowed max of 15`,
  doubleSpendInMempool: (txId, other) => `Rejected transaction ${txId}: output ${"11".repeat(32)}:0 already spent by transaction ${other} in the mempool`,
  /* the JS/WASM client's transport envelope around the same node answer */
  wrapped: (inner) => "RPC Server (remote error) -> ServerError { code: -32000, message: `" + inner + "` }",
  transportLost: () => "connection closed before response"
};

/* a mock node whose submitTransaction answers follow a script: each entry { before?, throw? }; an exhausted script accepts */
function scriptedRpc(baseRpc) {
  const s = { calls: 0, answers: [] };
  s.rpc = {
    ...baseRpc,
    async submitTransaction(a) {
      s.calls += 1;
      const next = s.answers.shift();
      if (next && next.before) await next.before();
      if (next && next.throw) throw new Error(next.throw);
      return baseRpc.submitTransaction(a);
    }
  };
  return s;
}

/*
 * Persist a request EXACTLY as the PRE-CORRECTION runtime persisted a "rejection" it had classified from the node's
 * answer alone: state SUBMISSION_REJECTED, the answer in `error`, no submissionOutcome / proof, the submission claim
 * released (the reviewer's reproduction rejection-recovery-02.json). Returns the persisted legacy record.
 */
async function persistLegacyNegative(store, category, key, record, answer) {
  const legacy = { ...record, state: "SUBMISSION_REJECTED", error: answer, updatedAt: new Date().toISOString() };
  delete legacy.submissionOutcome;
  delete legacy.submissionResponse;
  delete legacy.chain;
  await store.write(category, key, legacy);
  await store.remove(Categories.SUBMISSION_CLAIM, record.txId);
  return legacy;
}

module.exports = { KAS, H, toolchainSkip, mainnetConfig, tokenFixture, tokenPolicyFor, hdLeafFor, answers, scriptedRpc, persistLegacyNegative };
