"use strict";

/*
 * PolicyVault headless agent SDK.
 *
 * A minimal delegate interface for automation (bots, AI agents, service
 * accounts). It separates transaction preparation, signing, and
 * submission so a delegate's key material can live behind a pluggable
 * external signer and never inside PolicyVault.
 *
 *   getVault()            -> vault snapshot (status, policy, live state)
 *   getPolicy()           -> immutable policy (KAS-normalized)
 *   getRemainingBudget()  -> remaining period budget (sompi + KAS)
 *   prepareSpend()        -> validate against policy; return a spend plan
 *   signSpend()           -> (delegated to submitSpend's signer)
 *   submitSpend()         -> execute prepared spend via the SDK
 *   getSpendStatus()      -> receipt/status for a txid
 *
 * Signers implement { secret } (dev signer) or a custom adapter used by
 * the underlying SDK. A development signer is clearly labeled unsafe.
 */

const path = require("path");
const fs = require("fs");

const sdkRoot = path.join(__dirname, "..", "sdk");
const { loadConfig } = require(path.join(sdkRoot, "src/config"));
const { loadAnyManifest } = require(path.join(sdkRoot, "src/manifest-v2"));
const { spendFromVault } = require(path.join(sdkRoot, "src/spend-vault"));
const { spendFromVaultV2 } = require(path.join(sdkRoot, "src/vault-ops-v2"));
const { parsePositiveSompi, sompiToKas, kasToSompi } = require(path.join(sdkRoot, "src/amounts"));

function fail(message) {
  throw new Error(`agent-sdk: ${message}`);
}

/*
 * A development signer holding a raw test key. NEVER for production —
 * production delegates supply an external signer adapter. The label is
 * intentionally loud.
 */
function developmentSigner(secretHex, address, xonly) {
  if (!/^[0-9a-f]{64}$/.test(secretHex)) {
    fail("developmentSigner requires a 32-byte hex secret");
  }
  return { kind: "UNSAFE_DEV_SIGNER", secret: secretHex, address, xonly };
}

class PolicyVaultAgent {
  constructor({ vaultId, signer, configOverrides } = {}) {
    if (!vaultId) {
      fail("vaultId is required");
    }
    if (!signer || signer.kind !== "UNSAFE_DEV_SIGNER") {
      fail("v0.1 supports only the development signer; external signer adapters are a documented extension point");
    }
    this.vaultId = vaultId;
    this.signer = signer;
    this.config = loadConfig(configOverrides);
  }

  /*
   * Version-aware manifest access. Returns the normalized manifest with a
   * uniform `_policyView` (v0.1: immutable policy; v0.2: policy fields from
   * live state). Unknown manifest schemas fail closed in loadAnyManifest.
   */
  _manifest() {
    const loaded = loadAnyManifest(this.config, this.vaultId);
    if (!loaded) {
      fail(`no vault ${this.vaultId}`);
    }
    this._version = loaded.version;
    return loaded.manifest;
  }

  _policyView(m) {
    if (this._version === "v2") {
      if (!m.live) {
        fail("v0.2 vault has no live state — policy unavailable");
      }
      const s = m.live.state;
      return {
        owner: m.template.owner,
        delegate: s.delegate,
        maxPerSpend: s.maxPerSpend,
        periodBudget: s.periodBudget,
        periodLengthDaa: s.periodLengthDaa,
        recipients: [...s.recipients],
        declaredRecipientCount: 3,
        policyNonce: s.policyNonce,
        delegateActive: s.delegateActive === 1n
      };
    }
    return {
      owner: m.policy.owner,
      delegate: m.policy.delegate,
      maxPerSpend: m.policy.maxPerSpend,
      periodBudget: m.policy.periodBudget,
      periodLengthDaa: m.policy.periodLengthDaa,
      recipients: m.policy.recipients,
      declaredRecipientCount: m.policy.declaredRecipientCount,
      policyNonce: null,
      delegateActive: true
    };
  }

  getVault() {
    const m = this._manifest();
    return {
      vaultId: m.vaultId,
      status: m.status,
      networkId: m.networkId,
      live: m.live
        ? {
            protectedValueKas: sompiToKas(m.live.state.protectedValue),
            periodSpentKas: sompiToKas(m.live.state.periodSpent),
            paused: m.live.state.paused === 1n,
            outpoint: m.live.outpoint
          }
        : null
    };
  }

  getPolicy() {
    const m = this._manifest();
    const p = this._policyView(m);
    return {
      owner: p.owner,
      delegate: p.delegate,
      maxPerSpendKas: sompiToKas(p.maxPerSpend),
      periodBudgetKas: sompiToKas(p.periodBudget),
      periodLengthDaa: p.periodLengthDaa.toString(),
      recipients: p.recipients.slice(0, p.declaredRecipientCount),
      contractVersion: m.contractVersion,
      policyNonce: p.policyNonce === null ? null : p.policyNonce.toString(),
      delegateActive: p.delegateActive
    };
  }

  getRemainingBudget() {
    const m = this._manifest();
    if (!m.live) {
      fail("vault has no live state");
    }
    const p = this._policyView(m);
    const remaining = p.periodBudget - m.live.state.periodSpent;
    const clamped = remaining > 0n ? remaining : 0n;
    return { sompi: clamped.toString(), kas: sompiToKas(clamped) };
  }

  /*
   * Validate a spend against policy WITHOUT touching the chain. Returns a
   * plan the caller can inspect before submitting.
   */
  prepareSpend({ amountKas, amountSompi, recipientIndex }) {
    const m = this._manifest();
    if (m.status !== "ACTIVE") {
      fail(`vault status is ${m.status}`);
    }
    const p = this._policyView(m);
    if (!p.delegateActive) {
      fail("delegate is revoked — the covenant would reject any spend");
    }
    const pay = amountSompi !== undefined ? parsePositiveSompi(amountSompi, "amountSompi") : kasToSompi(String(amountKas));
    const idx = Number(recipientIndex);
    if (!Number.isInteger(idx) || idx < 1 || idx > p.declaredRecipientCount) {
      fail(`recipientIndex must be 1..${p.declaredRecipientCount}`);
    }
    if (pay > p.maxPerSpend) {
      fail(`amount ${sompiToKas(pay)} KAS exceeds per-spend cap ${sompiToKas(p.maxPerSpend)} KAS`);
    }
    const withinPeriod = m.live.state.periodSpent + pay <= p.periodBudget;
    return {
      vaultId: this.vaultId,
      contractVersion: m.contractVersion,
      payAmountSompi: pay.toString(),
      payAmountKas: sompiToKas(pay),
      recipientIndex: idx,
      recipient: p.recipients[idx - 1],
      requiresRollover: !withinPeriod,
      remainingBudgetKas: this.getRemainingBudget().kas
    };
  }

  /*
   * Execute a prepared spend. periodsElapsed lets a caller roll the period
   * when prepareSpend reported requiresRollover.
   */
  async submitSpend(plan, { periodsElapsed = 0 } = {}) {
    if (!plan || !plan.payAmountSompi) {
      fail("submitSpend requires a plan from prepareSpend");
    }
    this._manifest(); // refresh version
    const spend = this._version === "v2" ? spendFromVaultV2 : spendFromVault;
    const result = await spend({
      config: this.config,
      vaultId: this.vaultId,
      delegateKey: { secret: this.signer.secret, address: this.signer.address, xonly: this.signer.xonly },
      payAmount: BigInt(plan.payAmountSompi),
      recipientIndex: plan.recipientIndex,
      periodsElapsed
    });
    return { txId: result.txId, recipientAddress: result.recipientAddress };
  }

  getSpendStatus(txId) {
    const receiptPath = path.join(this.config.dataRoot, "receipts", `${txId}.json`);
    if (!fs.existsSync(receiptPath)) {
      return { txId, status: "UNKNOWN" };
    }
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    return { txId, status: "CHAIN_VERIFIED", action: receipt.action, proof: receipt.proof };
  }
}

module.exports = { PolicyVaultAgent, developmentSigner };
