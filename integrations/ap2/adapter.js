"use strict";

/*
 * AP2 adapter orchestration — stages [A], [B] and [H] of the spec's §4.1
 * flow, with C–G reached ONLY over the public Agent API under a scoped
 * machine credential. PolicyVault occupies exactly one AP2 role:
 * Credential Provider. It signs no mandate, holds no key, issues no
 * pull credential (there is no Kaspa primitive that lets a counterparty
 * later move vault funds, and PolicyVault never emulates one — §6.4),
 * and returns settlement only after real chain proof.
 *
 * Flow per presentation:
 *   verify SD-JWTs (pinned alg/_sd_alg, pinned anchors, key binding,
 *     disclosure completeness, exp/iat, checkout_hash)   <- authorship, NOT authorization
 *   closed-schema normalize + payee-directory resolution
 *   idempotency claim on the mandate transaction_id
 *   restrictive-only constraint evaluation (deny-wins; REVIEW handled
 *     fail-closed in v1 — see constraints.js header)
 *   allowlist pre-check -> MANDATORY dry run -> real build under the
 *     derived Idempotency-Key -> pending/reject -> submit (live-network
 *     gated) -> settlement ONLY from CHAIN_VERIFIED.
 */

const path = require("node:path");
const { createPolicyVaultClient, verifyServerNetwork, verifyLiveNetwork, NetworkGateError, PolicyVaultApiError } = require("../lib/pv-client");
const { AttemptStore } = require("../lib/attempt-store");
const { ap2MandateDigest, ap2IdempotencyKey } = require("../lib/digests");
const { sompiToKas } = require("../lib/amounts-gate");
const { addressForXOnlyPubkey } = require("../lib/address");
const { loadPayeeDirectory, loadPayeeDirectoryFile } = require("../lib/payee-directory");
const { pollForSettlement, classifyRequestState, settlementEvidenceFrom } = require("../lib/settlement");
const { verifySdJwtMandate } = require("./sdjwt");
const { SUPPORTED_VCT, normalizeClosedPaymentMandate, normalizeClosedCheckoutMandate, extractOpenMandateConstraints } = require("./normalize");
const { evaluateConstraints } = require("./constraints");
const { Ap2Refusal, EXPLANATIONS } = require("./codes");
const { sha256Hex } = require("../lib/canonical");

const ATTEMPT_SCHEMA = "policyvault-ap2-attempt/v1";
const HEX32_RE = /^[0-9a-f]{64}$/;
const SUBMISSION_CAP_BYTES = 262144; // 256 KiB per submission (spec §3.3)

/* Interim upstream literals — recorded in the evidence note:
 *  - instrument type: the spec's §6.3 proposed reverse-DNS literal
 *    (exact registration authority is OPEN, OQ-9);
 *  - currency: the spec's stated design choice — a non-ISO token pinned
 *    by the instrument type; deviates from AP2's ISO-4217 text, openly
 *    (OQ-4). */
const DEFAULT_INSTRUMENT_TYPE = "org.policy-vault.kaspa.covenant-vault.v1";
const DEFAULT_CURRENCY_LITERAL = "KAS";
const DEFAULT_REQUIRED_CONSTRAINTS = Object.freeze(["payment.amount_range", "payment.budget", "payment.allowed_payees"]);

const CONFIG_KEYS = Object.freeze(new Set([
  "networkId",
  "rustyKaspaModule",
  "policyVault",
  "dataDir",
  "trustAnchors",
  "instruments",
  "payeeDirectory",
  "payeeDirectoryFile",
  "instrumentType",
  "currencyLiteral",
  "requiredConstraintTypes",
  "clockSkewSeconds",
  "deadlineCeilingSeconds",
  "actorXOnly",
  "submitPollAttempts",
  "submitPollDelayMs"
]));

function buildConfig(options) {
  if (!options || typeof options !== "object") throw new Error("ap2 adapter: config object required");
  for (const key of Object.keys(options)) {
    if (!CONFIG_KEYS.has(key)) throw new Error(`ap2 adapter config: unknown key ${JSON.stringify(key)} — failing closed`);
  }
  const { networkId, rustyKaspaModule, dataDir, policyVault } = options;
  if (networkId !== "mainnet" && networkId !== "testnet-10") throw new Error(`ap2 adapter config: unsupported networkId ${JSON.stringify(networkId)} — failing closed`);
  if (typeof rustyKaspaModule !== "string" || !rustyKaspaModule) throw new Error("ap2 adapter config: rustyKaspaModule path is required");
  if (typeof dataDir !== "string" || !dataDir) throw new Error("ap2 adapter config: dataDir is required");
  if (!policyVault || typeof policyVault.baseUrl !== "string" || typeof policyVault.token !== "string") {
    throw new Error("ap2 adapter config: policyVault { baseUrl, token } is required");
  }
  if (options.instruments !== undefined) {
    for (const [handle, entry] of Object.entries(options.instruments)) {
      if (!entry || !HEX32_RE.test(entry.vaultId ?? "") || !HEX32_RE.test(entry.agentPk ?? "")) {
        throw new Error(`ap2 adapter config: instruments[${handle}] must map to { vaultId: 64-hex, agentPk: 64-hex }`);
      }
      if (Object.keys(entry).some((k) => k !== "vaultId" && k !== "agentPk")) {
        throw new Error(`ap2 adapter config: instruments[${handle}] carries unknown fields — failing closed`);
      }
    }
  }
  if (options.actorXOnly !== undefined && !HEX32_RE.test(options.actorXOnly)) throw new Error("ap2 adapter config: actorXOnly must be 64-hex when supplied");
  return Object.freeze({
    networkId,
    rustyKaspaModule,
    dataDir,
    policyVault: { baseUrl: policyVault.baseUrl, token: policyVault.token },
    trustAnchors: options.trustAnchors ?? null, // null => every verification fails closed (AP2_TRUST_ANCHOR_UNCONFIGURED)
    instruments: options.instruments ?? {},
    payeeDirectory: options.payeeDirectory ?? null,
    payeeDirectoryFile: options.payeeDirectoryFile ?? null,
    instrumentType: options.instrumentType ?? DEFAULT_INSTRUMENT_TYPE,
    currencyLiteral: options.currencyLiteral ?? DEFAULT_CURRENCY_LITERAL,
    requiredConstraintTypes: Object.freeze([...(options.requiredConstraintTypes ?? DEFAULT_REQUIRED_CONSTRAINTS)]),
    clockSkewSeconds: options.clockSkewSeconds ?? 120,
    deadlineCeilingSeconds: options.deadlineCeilingSeconds ?? 3600,
    actorXOnly: options.actorXOnly ?? null,
    submitPollAttempts: options.submitPollAttempts ?? 10,
    submitPollDelayMs: options.submitPollDelayMs ?? 500
  });
}

function report(record, { extraFields = null } = {}) {
  const out = {
    protocol: "ap2",
    transactionId: record.transactionId,
    status: record.outcome.status,
    stage: record.outcome.stage,
    codes: record.outcome.codes,
    explanations: record.outcome.codes.map((c) => EXPLANATIONS[c] ?? null),
    mandateDigest: record.mandateDigest,
    requestId: record.requestId ?? null,
    manifestHash: record.manifestHash ?? null,
    txId: record.txId ?? null
  };
  if (record.outcome.refusalReason) out.refusalReason = record.outcome.refusalReason;
  if (record.outcome.requires) out.requires = record.outcome.requires;
  if (record.settlement) out.settlement = record.settlement;
  if (record.constraints) out.constraints = record.constraints;
  if (extraFields) Object.assign(out, extraFields);
  return out;
}

class Ap2Adapter {
  constructor(options) {
    this.config = buildConfig(options);
    this.client = createPolicyVaultClient(this.config.policyVault);
    this.store = new AttemptStore({ dir: path.join(this.config.dataDir, "ap2-attempts") });
    this.addressConfig = Object.freeze({ networkId: this.config.networkId, rustyKaspaModule: this.config.rustyKaspaModule });
    // Directory addresses are resolved through the AUTHORITATIVE parser
    // at construction — a malformed or wrong-network entry fails the
    // deployment closed at startup, not one payment at a time.
    if (this.config.payeeDirectoryFile) {
      this.payeeDirectory = loadPayeeDirectoryFile(this.addressConfig, this.config.payeeDirectoryFile);
    } else if (this.config.payeeDirectory) {
      this.payeeDirectory = loadPayeeDirectory(this.addressConfig, this.config.payeeDirectory);
    } else {
      this.payeeDirectory = new Map(); // empty directory: every payee refuses (fail closed)
    }
  }

  /*
   * One mandate presentation from a Shopping Agent. Input (closed):
   *   { paymentMandate, checkoutMandate?, openPaymentMandate?,
   *     openCheckoutMandate?, expectedNonce? }
   * All mandates are compact SD-JWT strings. Returns the CP's
   * verification/authorization outcome document (§4.5 table) — the CP
   * declines or settles; it never emits a partial authorization.
   */
  async handlePaymentMandate(input) {
    // ---- caller input (closed schema) --------------------------------
    if (!input || typeof input !== "object") return this._inputRefusal("AP2_CALLER_INPUT_INVALID", "body must be an object");
    const allowed = new Set(["paymentMandate", "checkoutMandate", "openPaymentMandate", "openCheckoutMandate", "expectedNonce"]);
    for (const key of Object.keys(input)) {
      if (!allowed.has(key)) return this._inputRefusal("AP2_CALLER_INPUT_INVALID", `unknown field ${JSON.stringify(key)}`);
    }
    const totalBytes = ["paymentMandate", "checkoutMandate", "openPaymentMandate", "openCheckoutMandate"]
      .map((k) => (typeof input[k] === "string" ? Buffer.byteLength(input[k], "utf8") : 0))
      .reduce((a, b) => a + b, 0);
    if (totalBytes > SUBMISSION_CAP_BYTES) return this._inputRefusal("AP2_ENVELOPE_INVALID", `submission exceeds ${SUBMISSION_CAP_BYTES} bytes`);
    if (typeof input.paymentMandate !== "string" || !input.paymentMandate) {
      return this._inputRefusal("AP2_CALLER_INPUT_INVALID", "paymentMandate (compact SD-JWT) is required");
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const verifyOpts = { trustAnchors: this.config.trustAnchors, nowSeconds, clockSkewSeconds: this.config.clockSkewSeconds, expectedNonce: input.expectedNonce };

    // ---- [A] verify + [B] normalize (pure; a rejection here is FREE) --
    let verified;
    let normalized;
    let checkout = null;
    let openConstraints = [];
    let openPaymentDigestSource = null;
    const verificationEvidence = [];
    try {
      // Closed Payment Mandate (required).
      verified = verifySdJwtMandate(input.paymentMandate, verifyOpts);
      verificationEvidence.push({ vct: verified.claims.vct ?? null, ...verified.verification });
      normalized = normalizeClosedPaymentMandate(verified.claims, { config: this.config, payeeDirectory: this.payeeDirectory });

      // Closed Checkout Mandate (optional; digest-cross-checked).
      if (input.checkoutMandate !== undefined) {
        if (typeof input.checkoutMandate !== "string") return this._inputRefusal("AP2_CALLER_INPUT_INVALID", "checkoutMandate must be a string");
        const vc = verifySdJwtMandate(input.checkoutMandate, verifyOpts);
        verificationEvidence.push({ vct: vc.claims.vct ?? null, ...vc.verification });
        checkout = normalizeClosedCheckoutMandate(vc.claims, { expectedTransactionId: normalized.transactionId });
      }

      // Operating mode is established from WHAT WAS PRESENTED (A-23):
      // an agent-signed closed mandate is human-not-present and REQUIRES
      // a user-signed open Payment Mandate. A user-signed closed mandate
      // is human-present.
      const signerRole = verified.role;
      if (signerRole !== "user") {
        if (input.openPaymentMandate === undefined) {
          throw new Ap2Refusal("AP2_OPEN_MANDATE_REQUIRED", `closed mandate signer role is ${JSON.stringify(signerRole)}`);
        }
      }
      if (input.openPaymentMandate !== undefined) {
        if (typeof input.openPaymentMandate !== "string") return this._inputRefusal("AP2_CALLER_INPUT_INVALID", "openPaymentMandate must be a string");
        const vo = verifySdJwtMandate(input.openPaymentMandate, verifyOpts);
        verificationEvidence.push({ vct: vo.claims.vct ?? null, ...vo.verification });
        if (vo.role !== "user") throw new Ap2Refusal("AP2_KEY_BINDING_INVALID", "the open Payment Mandate must be signed by the USER trust anchor (the human pre-authorization)");
        openConstraints = openConstraints.concat(
          extractOpenMandateConstraints(vo.claims, { expectedVct: SUPPORTED_VCT.OPEN_PAYMENT, requiredConstraintTypes: this.config.requiredConstraintTypes })
        );
        openPaymentDigestSource = vo.raw;
      }
      if (input.openCheckoutMandate !== undefined) {
        if (typeof input.openCheckoutMandate !== "string") return this._inputRefusal("AP2_CALLER_INPUT_INVALID", "openCheckoutMandate must be a string");
        const vo = verifySdJwtMandate(input.openCheckoutMandate, verifyOpts);
        verificationEvidence.push({ vct: vo.claims.vct ?? null, ...vo.verification });
        if (vo.role !== "user") throw new Ap2Refusal("AP2_KEY_BINDING_INVALID", "the open Checkout Mandate must be signed by the USER trust anchor");
        openConstraints = openConstraints.concat(
          extractOpenMandateConstraints(vo.claims, { expectedVct: SUPPORTED_VCT.OPEN_CHECKOUT, requiredConstraintTypes: [] })
        );
      }
    } catch (error) {
      if (error instanceof Ap2Refusal) {
        return this._verifyRejection(error, input, verificationEvidence);
      }
      throw error;
    }

    // ---- idempotency: claim / replay / conflict on transaction_id -----
    const mandateDigest = ap2MandateDigest({
      vct: verified.claims.vct,
      transaction_id: normalized.transactionId,
      payee: verified.claims.payee,
      payment_amount: verified.claims.payment_amount,
      payment_instrument: verified.claims.payment_instrument,
      exp: verified.claims.exp
    });
    const existing = this.store.read(normalized.transactionId);
    if (existing) return this._continueExisting(existing, mandateDigest);

    const idempotencyKey = ap2IdempotencyKey({
      transaction_id: normalized.transactionId,
      paymentMandateDigest: mandateDigest,
      vaultId: normalized.vaultId,
      agentPk: normalized.agentPk
    });
    const deadlineEpochSeconds = Math.min(
      normalized.exp ?? nowSeconds + this.config.deadlineCeilingSeconds,
      nowSeconds + this.config.deadlineCeilingSeconds
    );
    const record = {
      schema: ATTEMPT_SCHEMA,
      transactionId: normalized.transactionId,
      idempotencyKey,
      mandateDigest,
      openMandateDigest: openPaymentDigestSource ? sha256Hex(openPaymentDigestSource) : null,
      requestId: null,
      manifestHash: null,
      txId: null,
      riskEvaluationId: null,
      vaultId: normalized.vaultId,
      networkId: this.config.networkId,
      agentPk: normalized.agentPk,
      actorXOnly: this.config.actorXOnly,
      normalized: {
        payAmountSompi: normalized.payAmountSompi,
        recipientXOnly: normalized.recipientXOnly,
        deadlineEpochSeconds
      },
      verification: { mandates: verificationEvidence, checkoutHashVerified: checkout ? checkout.checkoutJwtDisclosed : false },
      constraints: null,
      protocol: {
        protocol: "ap2",
        specVersion: "0.2",
        paymentMandateRaw: verified.raw,
        checkoutMandateRaw: typeof input.checkoutMandate === "string" ? input.checkoutMandate : null,
        openMandatesRaw: [input.openPaymentMandate, input.openCheckoutMandate].filter((m) => typeof m === "string"),
        payeeRaw: normalized.audit.payeeRaw,
        riskDataRaw: normalized.audit.riskDataRaw,
        settlementResponseRaw: null
      },
      outcome: { status: "IN_PROGRESS", stage: "verify", codes: [], at: new Date().toISOString() },
      outcomeHistory: [],
      createdAt: new Date().toISOString()
    };
    const claim = this.store.claim(normalized.transactionId, record);
    if (!claim.claimed) {
      const now = claim.existing;
      if (now && now.outcome && now.outcome.status === "IN_PROGRESS") {
        return { protocol: "ap2", transactionId: normalized.transactionId, status: "BUSY", stage: "claim", codes: ["AP2_ATTEMPT_IN_PROGRESS"], explanations: [EXPLANATIONS.AP2_ATTEMPT_IN_PROGRESS] };
      }
      return this._continueExisting(now, mandateDigest);
    }

    // ---- restrictive-only constraint evaluation (deny-wins) -----------
    const accounting = this._accountingForOpenMandate(record.openMandateDigest);
    const evaluation = evaluateConstraints(openConstraints, {
      payAmountSompi: normalized.payAmountSompi,
      payeeId: normalized.payeeId,
      instrumentHandle: normalized.instrumentHandle,
      transactionId: normalized.transactionId,
      currencyLiteral: this.config.currencyLiteral,
      nowSeconds,
      accounting
    });
    // Constraint evidence is additive, stored once through the store's
    // write-once channel (never rewritten thereafter).
    const constraintsBlock = { evaluated: evaluation.evaluated, riskDecision: evaluation.decision, riskCodes: evaluation.codes };
    this.store.transition(
      normalized.transactionId,
      { status: "IN_PROGRESS", stage: "normalize", codes: [] },
      { set: { constraints: constraintsBlock } }
    );
    if (evaluation.decision !== "ALLOW") {
      // v1 handles adapter-side REVIEW fail-closed (see constraints.js).
      const updated = this.store.transition(normalized.transactionId, {
        status: "REJECTED",
        stage: "normalize",
        codes: evaluation.codes.length ? evaluation.codes : ["AP2_CONSTRAINT_UNREADABLE"]
      });
      return report(updated, { extraFields: { constraintDecision: evaluation.decision } });
    }

    return this._drivePipeline(this.store.read(normalized.transactionId));
  }

  /* Budget/recurrence accounting for one open mandate: settled and
   * in-flight attempts CONSUME; rejected/failed/expired do not. Torn
   * records count against the budget (conservative). */
  _accountingForOpenMandate(openMandateDigest) {
    if (!openMandateDigest) return { consumedSompi: "0", occurrenceCount: 0 };
    let consumed = 0n;
    let occurrences = 0;
    for (const record of this.store.list()) {
      if (record === null) {
        occurrences += 1; // torn record: conservative
        continue;
      }
      if (record.openMandateDigest !== openMandateDigest) continue;
      const status = record.outcome ? record.outcome.status : null;
      if (status === "SETTLED" || status === "PENDING" || status === "IN_PROGRESS") {
        occurrences += 1;
        if (record.normalized && /^(0|[1-9][0-9]*)$/.test(record.normalized.payAmountSompi ?? "")) {
          consumed += BigInt(record.normalized.payAmountSompi);
        }
      }
    }
    return { consumedSompi: consumed.toString(), occurrenceCount: occurrences };
  }

  _continueExisting(record, newDigest) {
    if (record.mandateDigest !== newDigest) {
      return {
        protocol: "ap2",
        transactionId: record.transactionId,
        status: "REJECTED",
        stage: "idempotency",
        codes: ["IDEMPOTENCY_KEY_CONFLICT"],
        explanations: [EXPLANATIONS.IDEMPOTENCY_KEY_CONFLICT],
        mandateDigest: record.mandateDigest
      };
    }
    const status = record.outcome.status;
    if (status === "REJECTED" || status === "FAILED" || status === "EXPIRED") return report(record, { extraFields: { replayed: true } });
    if (status === "SETTLED") return report(record, { extraFields: { replayed: true } });
    if (status === "IN_PROGRESS") {
      return { protocol: "ap2", transactionId: record.transactionId, status: "BUSY", stage: "claim", codes: ["AP2_ATTEMPT_IN_PROGRESS"], explanations: [EXPLANATIONS.AP2_ATTEMPT_IN_PROGRESS] };
    }
    return this._drivePipeline(record);
  }

  async _drivePipeline(record) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (record.txId && record.outcome.status === "SETTLED") return report(record);
    if (record.requestId) return this._continueWithRequest(record, nowSeconds);

    if (nowSeconds > record.normalized.deadlineEpochSeconds) {
      const updated = this.store.transition(record.transactionId, { status: "EXPIRED", stage: "verify", codes: ["AP2_MANDATE_EXPIRED"] });
      return report(updated);
    }

    try {
      await verifyServerNetwork(this.client, this.config.networkId);
    } catch (error) {
      return this._retryableUpstream(record, "simulate", error);
    }

    // Allowlist pre-check (precise, free): the directory-resolved key
    // must already be a covenant-allowlisted recipient of the agent.
    try {
      const vault = await this.client.getVault(record.vaultId); // GET /vaults/:id serves the presented vault directly
      const agents = vault && Array.isArray(vault.agents) ? vault.agents : [];
      const entry = agents.find((a) => a && a.agentPk === record.agentPk);
      if (entry && Array.isArray(entry.recipients) && !entry.recipients.includes(record.normalized.recipientXOnly)) {
        const updated = this.store.transition(record.transactionId, { status: "REJECTED", stage: "normalize", codes: ["AP2_PAYEE_NOT_ALLOWLISTED"] });
        return report(updated);
      }
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        const updated = this.store.transition(record.transactionId, {
          status: "REJECTED",
          stage: "simulate",
          codes: [error.code],
          refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
        });
        return report(updated);
      }
      return this._retryableUpstream(record, "simulate", error);
    }

    // ---- [C] MANDATORY dry run ---------------------------------------
    const signerAddress = addressForXOnlyPubkey(this.addressConfig, record.agentPk);
    const body = {
      vaultId: record.vaultId,
      action: "agentSpend",
      params: { payAmountSompi: record.normalized.payAmountSompi, agentPk: record.agentPk, recipient: record.normalized.recipientXOnly },
      signerAddress
    };
    let answer;
    try {
      answer = await this.client.simulate(body);
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        const updated = this.store.transition(record.transactionId, {
          status: "REJECTED",
          stage: "simulate",
          codes: [error.code],
          refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
        });
        return report(updated);
      }
      return this._retryableUpstream(record, "simulate", error);
    }
    const sim = answer && answer.simulation ? answer.simulation : null;
    if (!sim || sim.ok !== true) {
      const rr = sim && sim.refusalReason ? sim.refusalReason : { status: 500, code: "SIMULATION_FAILED", message: "no simulation result" };
      const stage = rr.code === "RISK_DENIED" ? "simulate" : "simulate";
      const codes = [rr.code, ...(sim && sim.risk && Array.isArray(sim.risk.codes) ? sim.risk.codes : [])];
      const updated = this.store.transition(record.transactionId, { status: "REJECTED", stage, codes, refusalReason: rr });
      return report(updated);
    }
    const expectedKas = sompiToKas(BigInt(record.normalized.payAmountSompi));
    if (!sim.review || sim.review.paymentKas !== expectedKas) {
      const updated = this.store.transition(record.transactionId, { status: "REJECTED", stage: "simulate", codes: ["AP2_PAYMENT_MISMATCH"] });
      return report(updated);
    }

    // ---- [D] real durable build under the derived key ----------------
    let request;
    try {
      const built = await this.client.createRequest(body, { idempotencyKey: record.idempotencyKey });
      request = built.request;
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        if (error.code === "RISK_REVIEW_REQUIRED") {
          const evaluationId = error.extra && error.extra.riskEvaluation ? error.extra.riskEvaluation.evaluationId : null;
          const updated = this.store.transition(
            record.transactionId,
            { status: "PENDING", stage: "build", codes: ["RISK_REVIEW_REQUIRED"], requires: ["riskRelease"], refusalReason: { status: error.status, code: error.code, message: error.serverMessage } },
            { set: { riskEvaluationId: evaluationId } }
          );
          return report(updated, { extraFields: { evaluationId } });
        }
        const codes = [error.code, ...(error.extra && error.extra.riskEvaluation && Array.isArray(error.extra.riskEvaluation.codes) ? error.extra.riskEvaluation.codes : [])];
        const updated = this.store.transition(record.transactionId, {
          status: "REJECTED",
          stage: "build",
          codes,
          refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
        });
        return report(updated);
      }
      return this._retryableUpstream(record, "build", error);
    }

    let updated = this.store.transition(
      record.transactionId,
      { status: "IN_PROGRESS", stage: "build", codes: [] },
      { set: { requestId: request.requestId, manifestHash: request.manifestHash ?? null, txId: request.txId ?? null } }
    );

    // Post-build exact equality from the recorded intent manifest.
    if (request.manifestHash) {
      try {
        const rec = await this.client.getManifest(request.manifestHash);
        const payment = rec && rec.manifest ? rec.manifest.payment : null;
        if (!payment || String(payment.amountSompi) !== record.normalized.payAmountSompi || payment.recipientXOnly !== record.normalized.recipientXOnly) {
          updated = this.store.transition(record.transactionId, { status: "FAILED", stage: "build", codes: ["AP2_PAYMENT_MISMATCH"] });
          return report(updated);
        }
      } catch (error) {
        if (!(error instanceof PolicyVaultApiError)) return this._retryableUpstream(updated, "build", error);
        updated = this.store.transition(record.transactionId, { status: "FAILED", stage: "build", codes: ["AP2_PAYMENT_MISMATCH", error.code] });
        return report(updated);
      }
    }

    return this._continueWithRequest(this.store.read(record.transactionId), nowSeconds);
  }

  async _continueWithRequest(record, nowSeconds) {
    let request;
    try {
      const answer = await this.client.getRequest(record.requestId);
      request = answer.request;
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        const updated = this.store.transition(record.transactionId, {
          status: "FAILED",
          stage: "prove",
          codes: [error.code],
          refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
        });
        return report(updated);
      }
      return this._retryableUpstream(record, "prove", error);
    }
    const classification = classifyRequestState(request.state);
    if (classification === "SETTLED") {
      const evidence = settlementEvidenceFrom(request);
      const updated = this.store.transition(record.transactionId, { status: "SETTLED", stage: "prove", codes: [] }, { set: { settlement: evidence, txId: evidence.txId } });
      return report(updated, { extraFields: { settlement: { ...evidence, transaction_id: record.transactionId } } });
    }
    if (nowSeconds > record.normalized.deadlineEpochSeconds) {
      const updated = this.store.transition(record.transactionId, { status: "EXPIRED", stage: "prove", codes: ["AP2_MANDATE_EXPIRED"] });
      return report(updated, { extraFields: { requestState: request.state } });
    }
    if (classification === "PENDING_APPROVALS") {
      const requiredM = request.review && request.review.approvalsRequired ? request.review.approvalsRequired : null;
      const updated = this.store.transition(record.transactionId, { status: "PENDING", stage: "build", codes: [], requires: ["approvals", "signature"] });
      // Honest framing (§3.5): the amount exceeded the agent's covenant
      // approvalThreshold; an open mandate cannot lower a covenant tier.
      return report(updated, { extraFields: { requiredM, approvalProgress: request.approvalProgress ?? null, humanPresenceRequired: true, requestState: request.state } });
    }
    if (classification === "PENDING_SIGNATURE") {
      const updated = this.store.transition(record.transactionId, { status: "PENDING", stage: "sign", codes: [], requires: ["signature"] });
      return report(updated, { extraFields: { requestState: request.state } });
    }
    if (classification === "READY_TO_SUBMIT") {
      try {
        await verifyLiveNetwork(this.client, this.config.networkId);
      } catch (error) {
        if (error instanceof NetworkGateError) {
          const updated = this.store.transition(record.transactionId, { status: "PENDING", stage: "submit", codes: ["AP2_SUBMIT_BLOCKED", error.code], requires: ["retry"] });
          return report(updated, { extraFields: { detail: error.message } });
        }
        throw error;
      }
      try {
        await this.client.submitRequest(record.requestId);
      } catch (error) {
        if (error instanceof PolicyVaultApiError) {
          const updated = this.store.transition(record.transactionId, {
            status: "FAILED",
            stage: "submit",
            codes: [error.code],
            refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
          });
          return report(updated);
        }
        return this._retryableUpstream(record, "submit", error);
      }
      const polled = await pollForSettlement(this.client, record.requestId, { attempts: this.config.submitPollAttempts, delayMs: this.config.submitPollDelayMs });
      return this._afterPoll(record, polled);
    }
    if (classification === "IN_FLIGHT") {
      const polled = await pollForSettlement(this.client, record.requestId, { attempts: this.config.submitPollAttempts, delayMs: this.config.submitPollDelayMs });
      return this._afterPoll(record, polled);
    }
    if (classification === "UNKNOWN") {
      const updated = this.store.transition(record.transactionId, { status: "PENDING", stage: "prove", codes: [], requires: ["reconciliation"] });
      return report(updated, { extraFields: { requestState: request.state } });
    }
    const updated = this.store.transition(record.transactionId, { status: "FAILED", stage: "submit", codes: [request.state] });
    return report(updated, { extraFields: { requestState: request.state } });
  }

  _afterPoll(record, { classification, request }) {
    if (classification === "SETTLED") {
      const evidence = settlementEvidenceFrom(request);
      const updated = this.store.transition(record.transactionId, { status: "SETTLED", stage: "prove", codes: [] }, { set: { settlement: evidence, txId: evidence.txId } });
      return report(updated, { extraFields: { settlement: { ...evidence, transaction_id: record.transactionId } } });
    }
    if (classification === "UNKNOWN" || classification === "IN_FLIGHT") {
      const updated = this.store.transition(record.transactionId, { status: "PENDING", stage: "prove", codes: [], requires: ["reconciliation"] });
      return report(updated, { extraFields: { requestState: request ? request.state : null } });
    }
    const updated = this.store.transition(record.transactionId, { status: "FAILED", stage: "submit", codes: [request ? request.state : "UNKNOWN"] });
    return report(updated);
  }

  /* Cryptographic / normalization rejections BEFORE an attempt record
   * can exist (no transaction anchor yet, or refusing to bind one):
   * reported directly, deterministically, with the verification evidence
   * collected so far. */
  _verifyRejection(error, input, verificationEvidence) {
    return {
      protocol: "ap2",
      transactionId: null,
      status: "REJECTED",
      stage: "verify",
      codes: [error.code],
      explanations: [error.explanation],
      detail: error.detail,
      verification: { mandates: verificationEvidence }
    };
  }

  _inputRefusal(code, detail) {
    return { protocol: "ap2", transactionId: null, status: "REJECTED", stage: "input", codes: [code], explanations: [EXPLANATIONS[code]], detail: detail ?? null };
  }

  getAttempt(transactionId) {
    if (typeof transactionId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(transactionId)) return null;
    return this.store.read(transactionId);
  }

  _retryableUpstream(record, stage, error) {
    const code = error instanceof NetworkGateError && error.code === "NETWORK_MISMATCH" ? "AP2_UPSTREAM_UNAVAILABLE" : "AP2_UPSTREAM_UNAVAILABLE";
    const detail = error && error.message ? error.message : String(error);
    const updated = this.store.transition(record.transactionId, { status: "PENDING", stage, codes: [code], requires: ["retry"], detail });
    return report(updated);
  }
}

module.exports = { Ap2Adapter, ATTEMPT_SCHEMA, DEFAULT_INSTRUMENT_TYPE, DEFAULT_CURRENCY_LITERAL, DEFAULT_REQUIRED_CONSTRAINTS };
