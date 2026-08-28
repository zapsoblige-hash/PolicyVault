"use strict";

/*
 * x402 adapter orchestration — stages [A] and [G] of the spec's §4.1
 * flow. Stages B–F are UNTOUCHED existing PolicyVault surfaces reached
 * over the public Agent API with a scoped machine credential; this
 * process holds no key, signs nothing, and has no privileged path.
 *
 * Flow per attempt (all refusals surface as protocol-correct outcomes
 * with machine codes + deterministic explanations, §4.5):
 *   normalize (pure)                          -> refusals are FREE
 *   attempt claim (create-only, per attemptId)-> replay/conflict answers
 *   deadline gate
 *   capabilities network gate (Agent API's reported networkId)
 *   allowlist pre-check (read:vaults)         -> precise refusal, free
 *   MANDATORY dry run (POST /wallet/v4/simulate)
 *   exact-amount assertion from the simulated review
 *   real build (POST /wallet/v4/requests + derived Idempotency-Key)
 *   post-build manifest equality (read:manifests, exact sompi)
 *   pending / refusal reporting
 *   re-drive: signature/approvals progress -> live-network gate ->
 *   submit -> poll -> settlement ONLY from CHAIN_VERIFIED
 *
 * The adapter NEVER: holds keys, signs, converts units, adds recipients,
 * releases holds, approves, reconciles, queries a node, retries a 402
 * twice for one attemptId+digest, or reports settled before chain proof.
 */

const path = require("node:path");
const { createPolicyVaultClient, verifyServerNetwork, verifyLiveNetwork, NetworkGateError, PolicyVaultApiError, PolicyVaultNetworkError } = require("../lib/pv-client");
const { AttemptStore } = require("../lib/attempt-store");
const { x402IdempotencyKey, x402RequirementDigest } = require("../lib/digests");
const { sompiToKas } = require("../lib/amounts-gate");
const { addressForXOnlyPubkey } = require("../lib/address");
const { normalizePaymentRequired, buildPaymentSignatureHeader } = require("./normalize");
const { pollForSettlement, classifyRequestState, settlementEvidenceFrom } = require("../lib/settlement");
const { decodeBase64Strict, utf8TextOf, GuardError } = require("../lib/json-guard");
const { refusal, X402Refusal, EXPLANATIONS } = require("./codes");

const ATTEMPT_SCHEMA = "policyvault-x402-attempt/v1";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX32_RE = /^[0-9a-f]{64}$/;

/* CAIP-2-shaped network ids for Kaspa — spec §6.3 interim proposal,
 * explicitly UNVERIFIED upstream (OQ-5): no registered CAIP-2 namespace
 * for Kaspa is known. Config may override; unknown networks fail closed. */
const DEFAULT_CAIP2 = Object.freeze({ mainnet: "kaspa:mainnet", "testnet-10": "kaspa:testnet-10" });

const CONFIG_KEYS = Object.freeze(new Set([
  "networkId",
  "caip2NetworkId",
  "assetLiteral",
  "rustyKaspaModule",
  "policyVault",
  "dataDir",
  "actorXOnly",
  "submitPollAttempts",
  "submitPollDelayMs"
]));

function buildConfig(options) {
  if (!options || typeof options !== "object") throw new Error("x402 adapter: config object required");
  for (const key of Object.keys(options)) {
    if (!CONFIG_KEYS.has(key)) throw new Error(`x402 adapter config: unknown key ${JSON.stringify(key)} — failing closed`);
  }
  const { networkId, rustyKaspaModule, assetLiteral, dataDir, policyVault } = options;
  if (networkId !== "mainnet" && networkId !== "testnet-10") throw new Error(`x402 adapter config: unsupported networkId ${JSON.stringify(networkId)} — failing closed`);
  if (typeof rustyKaspaModule !== "string" || !rustyKaspaModule) throw new Error("x402 adapter config: rustyKaspaModule path is required (authoritative address parser)");
  if (typeof assetLiteral !== "string" || !assetLiteral) {
    // OQ-6 is OPEN upstream: there is no agreed asset literal for native
    // KAS. The conservative option is NO default — unconfigured refuses
    // everything rather than inventing protocol compatibility.
    throw new Error("x402 adapter config: assetLiteral is required and has no default (spec OQ-6 is unresolved — configure the deployment's agreed native-KAS sentinel)");
  }
  if (typeof dataDir !== "string" || !dataDir) throw new Error("x402 adapter config: dataDir is required");
  if (!policyVault || typeof policyVault.baseUrl !== "string" || typeof policyVault.token !== "string") {
    throw new Error("x402 adapter config: policyVault { baseUrl, token } is required");
  }
  const caip2 = options.caip2NetworkId ?? DEFAULT_CAIP2[networkId];
  if (typeof caip2 !== "string" || !caip2) throw new Error("x402 adapter config: caip2NetworkId could not be derived");
  if (options.actorXOnly !== undefined && !HEX32_RE.test(options.actorXOnly)) throw new Error("x402 adapter config: actorXOnly must be 64-hex when supplied");
  return Object.freeze({
    networkId,
    caip2NetworkId: caip2,
    assetLiteral,
    rustyKaspaModule,
    dataDir,
    actorXOnly: options.actorXOnly ?? null,
    submitPollAttempts: options.submitPollAttempts ?? 10,
    submitPollDelayMs: options.submitPollDelayMs ?? 500,
    policyVault: { baseUrl: policyVault.baseUrl, token: policyVault.token }
  });
}

/* Outcome documents returned to the adapter's caller (§4.5 table). Every
 * code carries its deterministic explanation. */
function report(record, { requires = null, extraFields = null } = {}) {
  const out = {
    protocol: "x402",
    attemptId: record.attemptId,
    status: record.outcome.status,
    stage: record.outcome.stage,
    codes: record.outcome.codes,
    explanations: record.outcome.codes.map((c) => EXPLANATIONS[c] ?? null),
    requirementDigest: record.requirementDigest,
    requestId: record.requestId ?? null,
    manifestHash: record.manifestHash ?? null,
    txId: record.txId ?? null
  };
  if (record.outcome.refusalReason) out.refusalReason = record.outcome.refusalReason;
  if (requires) out.requires = requires;
  if (record.outcome.requires) out.requires = record.outcome.requires;
  if (record.settlement) out.settlement = record.settlement;
  if (extraFields) Object.assign(out, extraFields);
  return out;
}

class X402Adapter {
  constructor(options) {
    this.config = buildConfig(options);
    this.client = createPolicyVaultClient(this.config.policyVault);
    this.store = new AttemptStore({ dir: path.join(this.config.dataDir, "x402-attempts") });
    /* Minimal config object for the authoritative address modules —
     * shaped like the SDK's config where address-identity reads it. */
    this.addressConfig = Object.freeze({ networkId: this.config.networkId, rustyKaspaModule: this.config.rustyKaspaModule, caip2NetworkId: this.config.caip2NetworkId, assetLiteral: this.config.assetLiteral });
  }

  /*
   * One logical purchase attempt. `attemptId` is caller-supplied and
   * MANDATORY. Returns an outcome document; never throws for protocol
   * outcomes (only for adapter-internal invariant violations).
   */
  async handleAttempt(input) {
    // ---- caller input (closed schema) --------------------------------
    if (!input || typeof input !== "object") return this._callerRefusal(null, "X402_CALLER_INPUT_INVALID", "body must be an object");
    const allowed = new Set(["attemptId", "vaultId", "agentPk", "paymentRequiredHeader"]);
    for (const key of Object.keys(input)) {
      if (!allowed.has(key)) return this._callerRefusal(null, "X402_CALLER_INPUT_INVALID", `unknown field ${JSON.stringify(key)}`);
    }
    const { attemptId, vaultId, agentPk, paymentRequiredHeader } = input;
    if (attemptId === undefined || attemptId === null || attemptId === "") {
      return this._callerRefusal(null, "X402_ATTEMPT_ID_REQUIRED", "the adapter never mints an attemptId");
    }
    if (typeof attemptId !== "string" || !UUID_RE.test(attemptId)) {
      return this._callerRefusal(null, "X402_CALLER_INPUT_INVALID", "attemptId must be a lowercase UUID");
    }
    if (typeof vaultId !== "string" || !HEX32_RE.test(vaultId)) return this._callerRefusal(attemptId, "X402_CALLER_INPUT_INVALID", "vaultId must be 64-hex");
    if (typeof agentPk !== "string" || !HEX32_RE.test(agentPk)) return this._callerRefusal(attemptId, "X402_CALLER_INPUT_INVALID", "agentPk must be 64-hex");
    if (typeof paymentRequiredHeader !== "string" || !paymentRequiredHeader) {
      return this._callerRefusal(attemptId, "X402_CALLER_INPUT_INVALID", "paymentRequiredHeader (base64 PAYMENT-REQUIRED value) is required");
    }

    // ---- [A] closed-schema normalization (pure, free) ----------------
    let norm = null;
    let normRefusal = null;
    try {
      norm = normalizePaymentRequired(paymentRequiredHeader, { config: this.addressConfig, receiveTimeMs: Date.now() });
    } catch (error) {
      if (error instanceof X402Refusal) normRefusal = error;
      else throw error;
    }

    // ---- attempt idempotency: claim / replay / conflict --------------
    const digest = norm ? norm.requirementDigest : null;
    const existing = this.store.read(attemptId);
    if (existing) return this._continueExisting(existing, digest);

    if (normRefusal) {
      // Record the refusal (auditable, replayable), consuming nothing.
      const record = this._createRecord({ attemptId, vaultId, agentPk, norm: null, normRefusal, digest: null, rawHeaderText: null });
      return report(record, { extraFields: normRefusal.perEntryRefusals ? { perEntryRefusals: normRefusal.perEntryRefusals } : null });
    }

    const idempotencyKey = x402IdempotencyKey({ attemptId, requirementDigest: digest, vaultId, agentPk });
    const record = {
      schema: ATTEMPT_SCHEMA,
      attemptId,
      idempotencyKey,
      requirementDigest: digest,
      requestId: null,
      manifestHash: null,
      txId: null,
      riskEvaluationId: null,
      vaultId,
      networkId: this.config.networkId,
      agentPk,
      actorXOnly: this.config.actorXOnly,
      normalized: {
        payAmountSompi: norm.normalized.payAmountSompi,
        recipientXOnly: norm.normalized.recipientXOnly,
        deadlineEpochSeconds: norm.normalized.deadlineEpochSeconds
      },
      echo: {
        selectedIndex: norm.selected.index,
        resourceRaw: norm.resourceRaw,
        acceptedRaw: norm.selected.raw,
        extensionsRaw: norm.extensionsRaw
      },
      protocol: {
        protocol: "x402",
        x402Version: norm.audit.x402Version,
        selectedIndex: norm.audit.selectedIndex,
        paymentRequiredRaw: norm.audit.paymentRequiredRaw,
        settlementResponseRaw: null
      },
      outcome: { status: "IN_PROGRESS", stage: "normalize", codes: [], at: new Date().toISOString() },
      outcomeHistory: [],
      createdAt: new Date().toISOString()
    };
    const claim = this.store.claim(attemptId, record);
    if (!claim.claimed) {
      const now = claim.existing;
      if (now && now.outcome && now.outcome.status === "IN_PROGRESS") {
        return { protocol: "x402", attemptId, status: "BUSY", stage: "claim", codes: ["X402_ATTEMPT_IN_PROGRESS"], explanations: [EXPLANATIONS.X402_ATTEMPT_IN_PROGRESS] };
      }
      return this._continueExisting(now, digest);
    }

    return this._drivePipeline(this.store.read(attemptId), norm);
  }

  /* Re-drive / replay semantics (§3.4): same attemptId + same digest ->
   * continue or replay verbatim; different digest -> deterministic
   * conflict, the build handler is never called. */
  async _continueExisting(record, newDigest) {
    if (record.requirementDigest !== newDigest) {
      return {
        protocol: "x402",
        attemptId: record.attemptId,
        status: "REFUSED",
        stage: "idempotency",
        codes: ["IDEMPOTENCY_KEY_CONFLICT"],
        explanations: [EXPLANATIONS.IDEMPOTENCY_KEY_CONFLICT],
        requirementDigest: record.requirementDigest
      };
    }
    const status = record.outcome.status;
    if (status === "REFUSED" || status === "FAILED" || status === "EXPIRED") {
      return report(record, { extraFields: { replayed: true } });
    }
    if (status === "SETTLED") {
      return this._settledReport(record, { replayed: true });
    }
    if (status === "IN_PROGRESS") {
      return { protocol: "x402", attemptId: record.attemptId, status: "BUSY", stage: "claim", codes: ["X402_ATTEMPT_IN_PROGRESS"], explanations: [EXPLANATIONS.X402_ATTEMPT_IN_PROGRESS] };
    }
    // PENDING: continue the pipeline from durable facts.
    return this._drivePipeline(record, null);
  }

  /*
   * Drive as far as durable facts allow. `norm` is non-null only on the
   * first pass (fresh normalization); continuation passes rebuild what
   * they need from the record.
   */
  async _drivePipeline(record, norm) {
    const nowSeconds = Math.floor(Date.now() / 1000);

    // A settled payment reports settled forever, deadline or not — money
    // moved; truth over timers. Otherwise an elapsed deadline expires the
    // attempt WITHOUT cancelling anything.
    if (record.txId && record.outcome.status === "SETTLED") return this._settledReport(record, {});

    // Continuation with a durable request: read its state FIRST — if the
    // chain already proved the payment, deadline no longer matters.
    if (record.requestId) return this._continueWithRequest(record, nowSeconds);

    if (nowSeconds > record.normalized.deadlineEpochSeconds) {
      const updated = this.store.transition(record.attemptId, { status: "EXPIRED", stage: "deadline", codes: ["X402_DEADLINE_ELAPSED"] });
      return report(updated);
    }

    // ---- network context: the Agent API's reported networkId ---------
    try {
      await verifyServerNetwork(this.client, this.config.networkId);
    } catch (error) {
      return this._retryableUpstream(record, "network", error);
    }

    // ---- allowlist pre-check (precise, free) -------------------------
    try {
      const vault = await this.client.getVault(record.vaultId); // GET /vaults/:id serves the presented vault directly
      const agents = vault && Array.isArray(vault.agents) ? vault.agents : [];
      const entry = agents.find((a) => a && a.agentPk === record.agentPk);
      if (entry && Array.isArray(entry.recipients) && !entry.recipients.includes(record.normalized.recipientXOnly)) {
        const updated = this.store.transition(record.attemptId, { status: "REFUSED", stage: "normalize", codes: ["X402_DESTINATION_NOT_ALLOWLISTED"] });
        return report(updated);
      }
      // Agent entry missing -> let the pipeline's own authorization gate
      // report precisely at simulate (never guessed here).
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        const updated = this.store.transition(record.attemptId, {
          status: "REFUSED",
          stage: "vault",
          codes: [error.code],
          refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
        });
        return report(updated);
      }
      return this._retryableUpstream(record, "vault", error);
    }

    // ---- [B] MANDATORY dry run ---------------------------------------
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
        const updated = this.store.transition(record.attemptId, {
          status: "REFUSED",
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
      const stage = rr.code === "RISK_DENIED" ? "risk" : "simulate";
      const codes = [rr.code, ...(sim && sim.risk && Array.isArray(sim.risk.codes) ? sim.risk.codes : [])];
      const updated = this.store.transition(record.attemptId, { status: "REFUSED", stage, codes, refusalReason: rr });
      return report(updated);
    }

    // ---- x402 `exact` equality, asserted from the simulated review ----
    // (fee is paid from the covenant fee reserve, never deducted from the
    // payment output, so the output must equal `amount` EXACTLY).
    const expectedKas = sompiToKas(BigInt(record.normalized.payAmountSompi));
    if (!sim.review || sim.review.paymentKas !== expectedKas) {
      const updated = this.store.transition(record.attemptId, { status: "REFUSED", stage: "simulate", codes: ["X402_PAYMENT_MISMATCH"] });
      return report(updated);
    }

    // ---- [C] the real durable build, under the derived key -----------
    let request;
    try {
      const answer = await this.client.createRequest(body, { idempotencyKey: record.idempotencyKey });
      request = answer.request;
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        if (error.code === "RISK_REVIEW_REQUIRED") {
          const evaluationId = error.extra && error.extra.riskEvaluation ? error.extra.riskEvaluation.evaluationId : null;
          const updated = this.store.transition(
            record.attemptId,
            { status: "PENDING", stage: "risk", codes: ["RISK_REVIEW_REQUIRED"], requires: ["riskRelease"], refusalReason: { status: error.status, code: error.code, message: error.serverMessage } },
            { set: { riskEvaluationId: evaluationId } }
          );
          return report(updated, { extraFields: { evaluationId } });
        }
        const stage = error.code === "RISK_DENIED" ? "risk" : "build";
        const codes = [error.code, ...(error.extra && error.extra.riskEvaluation && Array.isArray(error.extra.riskEvaluation.codes) ? error.extra.riskEvaluation.codes : [])];
        const updated = this.store.transition(record.attemptId, {
          status: "REFUSED",
          stage,
          codes,
          refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
        });
        return report(updated);
      }
      // Transport failure AFTER a build POST: unknown whether it
      // executed. The derived Idempotency-Key makes the re-drive safe —
      // report retryable, never a second key.
      return this._retryableUpstream(record, "build", error);
    }

    let updated = this.store.transition(
      record.attemptId,
      { status: "IN_PROGRESS", stage: "build", codes: [] },
      { set: { requestId: request.requestId, manifestHash: request.manifestHash ?? null, txId: request.txId ?? null } }
    );

    // ---- post-build exact equality from the recorded intent manifest --
    // (exact sompi + exact recipient, from what the verifier actually
    // committed to — never assumed).
    if (request.manifestHash) {
      try {
        const rec = await this.client.getManifest(request.manifestHash);
        const payment = rec && rec.manifest ? rec.manifest.payment : null;
        if (!payment || String(payment.amountSompi) !== record.normalized.payAmountSompi || payment.recipientXOnly !== record.normalized.recipientXOnly) {
          updated = this.store.transition(record.attemptId, { status: "FAILED", stage: "build", codes: ["X402_PAYMENT_MISMATCH"] });
          return report(updated);
        }
      } catch (error) {
        if (!(error instanceof PolicyVaultApiError)) return this._retryableUpstream(updated, "build", error);
        // A manifest we cannot read is a fail-closed refusal to proceed.
        updated = this.store.transition(record.attemptId, { status: "FAILED", stage: "build", codes: ["X402_PAYMENT_MISMATCH", error.code] });
        return report(updated);
      }
    }

    return this._continueWithRequest(this.store.read(record.attemptId), nowSeconds);
  }

  /* Continuation once a durable request exists: report pending states
   * honestly; submit ONLY behind the live-network gate; settle ONLY from
   * CHAIN_VERIFIED. */
  async _continueWithRequest(record, nowSeconds) {
    let request;
    try {
      const answer = await this.client.getRequest(record.requestId);
      request = answer.request;
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        const updated = this.store.transition(record.attemptId, {
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
      const updated = this.store.transition(
        record.attemptId,
        { status: "SETTLED", stage: "prove", codes: [] },
        { set: { settlement: evidence, txId: evidence.txId } }
      );
      return this._settledReport(updated, {});
    }

    if (nowSeconds > record.normalized.deadlineEpochSeconds) {
      // Elapsed before chain proof: report expired WITHOUT cancelling
      // anything — a broadcast Kaspa transaction is not cancellable and
      // reconciliation remains the only truth.
      const updated = this.store.transition(record.attemptId, { status: "EXPIRED", stage: "deadline", codes: ["X402_DEADLINE_ELAPSED"] });
      return report(updated, { extraFields: { requestState: request.state } });
    }

    if (classification === "PENDING_APPROVALS") {
      const requiredM = request.review && request.review.approvalsRequired ? request.review.approvalsRequired : null;
      const updated = this.store.transition(record.attemptId, { status: "PENDING", stage: "build", codes: [], requires: ["approvals", "signature"] });
      return report(updated, { extraFields: { requiredM, approvalProgress: request.approvalProgress ?? null, requestState: request.state } });
    }
    if (classification === "PENDING_SIGNATURE") {
      const updated = this.store.transition(record.attemptId, { status: "PENDING", stage: "sign", codes: [], requires: ["signature"] });
      return report(updated, { extraFields: { requestState: request.state } });
    }

    if (classification === "READY_TO_SUBMIT") {
      // The ONE live operation: verify network + sync + UTXO index first.
      try {
        await verifyLiveNetwork(this.client, this.config.networkId);
      } catch (error) {
        if (error instanceof NetworkGateError) {
          const updated = this.store.transition(record.attemptId, { status: "PENDING", stage: "submit", codes: ["X402_SUBMIT_BLOCKED", error.code], requires: ["retry"] });
          return report(updated, { extraFields: { detail: error.message } });
        }
        throw error;
      }
      try {
        await this.client.submitRequest(record.requestId);
      } catch (error) {
        if (error instanceof PolicyVaultApiError) {
          const updated = this.store.transition(record.attemptId, {
            status: "FAILED",
            stage: "submit",
            codes: [error.code],
            refusalReason: { status: error.status, code: error.code, message: error.serverMessage }
          });
          return report(updated);
        }
        // Unknown whether the broadcast happened: fail closed into the
        // poller; the durable claims + reconciliation own the truth.
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
      const updated = this.store.transition(record.attemptId, { status: "PENDING", stage: "prove", codes: [], requires: ["reconciliation"] });
      return report(updated, { extraFields: { requestState: request.state } });
    }

    // Fail-closed request states.
    const updated = this.store.transition(record.attemptId, { status: "FAILED", stage: "submit", codes: [request.state] });
    return report(updated, { extraFields: { requestState: request.state } });
  }

  _afterPoll(record, { classification, request }) {
    if (classification === "SETTLED") {
      const evidence = settlementEvidenceFrom(request);
      const updated = this.store.transition(
        record.attemptId,
        { status: "SETTLED", stage: "prove", codes: [] },
        { set: { settlement: evidence, txId: evidence.txId } }
      );
      return this._settledReport(updated, {});
    }
    if (classification === "UNKNOWN" || classification === "IN_FLIGHT") {
      const updated = this.store.transition(record.attemptId, { status: "PENDING", stage: "prove", codes: [], requires: ["reconciliation"] });
      return report(updated, { extraFields: { requestState: request ? request.state : null } });
    }
    const updated = this.store.transition(record.attemptId, { status: "FAILED", stage: "submit", codes: [request ? request.state : "UNKNOWN"] });
    return report(updated);
  }

  /* SETTLED report: settlement evidence + the PAYMENT-SIGNATURE header
   * material (byte-verbatim accepted/resource/extensions echo). The
   * caller performs the single retry of the original request; it reports
   * the outcome back via recordDeliveryResult. */
  _settledReport(record, { replayed }) {
    const settlement = record.settlement;
    const signature = buildPaymentSignatureHeader({
      resourceRaw: record.echo.resourceRaw,
      acceptedRaw: record.echo.acceptedRaw,
      extensionsRaw: record.echo.extensionsRaw,
      txId: settlement.txId,
      payAmountSompi: record.normalized.payAmountSompi
    });
    return report(record, {
      extraFields: {
        settlement,
        paymentSignature: { header: "PAYMENT-SIGNATURE", value: signature.headerValue },
        ...(replayed ? { replayed: true } : {})
      }
    });
  }

  /*
   * The caller's report of what the resource server answered AFTER the
   * settled retry. `PAYMENT-RESPONSE` content is recorded VERBATIM under
   * protocol.* (read by nothing); a refusal after settlement is the
   * paid-but-not-delivered event — a HUMAN-notification outcome, never
   * auto-retried, and it never alters outcome.status truth (X-15).
   */
  recordDeliveryResult({ attemptId, delivered, paymentResponseHeader }) {
    if (typeof attemptId !== "string" || !UUID_RE.test(attemptId)) return this._callerRefusal(null, "X402_CALLER_INPUT_INVALID", "attemptId must be a UUID");
    const record = this.store.read(attemptId);
    if (!record) return this._callerRefusal(attemptId, "X402_CALLER_INPUT_INVALID", "unknown attemptId");
    if (record.outcome.status !== "SETTLED") return this._callerRefusal(attemptId, "X402_CALLER_INPUT_INVALID", "delivery results apply only to settled attempts");
    let responseRaw = null;
    if (paymentResponseHeader !== undefined) {
      try {
        responseRaw = utf8TextOf(decodeBase64Strict(paymentResponseHeader, { maxEncodedBytes: 21848 }), "X402_HEADER_INVALID");
      } catch (error) {
        if (error instanceof GuardError || error instanceof X402Refusal) return this._callerRefusal(attemptId, "X402_HEADER_INVALID", "PAYMENT-RESPONSE header is not canonical base64 text");
        throw error;
      }
    }
    if (delivered === true) {
      const updated = this.store.transition(attemptId, { status: "SETTLED", stage: "deliver", codes: [] }, { set: { ...(responseRaw !== null ? { settlementResponseRaw: responseRaw } : {}), delivery: { delivered: true } } });
      return report(updated);
    }
    const updated = this.store.transition(
      attemptId,
      { status: "SETTLED", stage: "deliver", codes: ["X402_SERVER_REFUSED_AFTER_SETTLEMENT"], humanEscalation: true },
      { set: { ...(responseRaw !== null ? { settlementResponseRaw: responseRaw } : {}), delivery: { delivered: false, humanEscalation: true } } }
    );
    return report(updated, { extraFields: { humanEscalation: true } });
  }

  getAttempt(attemptId) {
    if (typeof attemptId !== "string" || !UUID_RE.test(attemptId)) return null;
    return this.store.read(attemptId);
  }

  _createRecord({ attemptId, vaultId, agentPk, normRefusal }) {
    const record = {
      schema: ATTEMPT_SCHEMA,
      attemptId,
      idempotencyKey: null,
      requirementDigest: null,
      requestId: null,
      manifestHash: null,
      txId: null,
      riskEvaluationId: null,
      vaultId,
      networkId: this.config.networkId,
      agentPk,
      actorXOnly: this.config.actorXOnly,
      normalized: null,
      echo: null,
      protocol: { protocol: "x402", x402Version: null, selectedIndex: null, paymentRequiredRaw: null, settlementResponseRaw: null },
      outcome: { status: "REFUSED", stage: "normalize", codes: [normRefusal.code], detail: normRefusal.detail, at: new Date().toISOString() },
      outcomeHistory: [],
      createdAt: new Date().toISOString()
    };
    const claim = this.store.claim(attemptId, record);
    if (!claim.claimed) return claim.existing;
    return record;
  }

  _retryableUpstream(record, stage, error) {
    const code = error instanceof NetworkGateError ? (error.code === "NETWORK_MISMATCH" ? "X402_NETWORK_MISMATCH" : "X402_UPSTREAM_UNAVAILABLE") : "X402_UPSTREAM_UNAVAILABLE";
    const detail = error && error.message ? error.message : String(error);
    const updated = this.store.transition(record.attemptId, { status: "PENDING", stage, codes: [code], requires: ["retry"], detail });
    return report(updated);
  }

  _callerRefusal(attemptId, code, detail) {
    return { protocol: "x402", attemptId: attemptId ?? null, status: "REFUSED", stage: "input", codes: [code], explanations: [EXPLANATIONS[code]], detail: detail ?? null };
  }
}

module.exports = { X402Adapter, ATTEMPT_SCHEMA, DEFAULT_CAIP2, refusal };
