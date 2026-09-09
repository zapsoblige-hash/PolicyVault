"use strict";

/*
 * The facilitator core (spec §7–§10): parse → principal constraints →
 * replay / destination-reuse state → node observation → deterministic
 * verification → (settle only) atomic single-use claim + evidence.
 * `/verify` NEVER writes state. Every response is JSON with a code from
 * the closed set. Nothing here signs, broadcasts, escrows, converts, or
 * calls a PolicyVault API.
 */

const { canonicalJsonStringify, domainDigestHex } = require("../lib/canonical");
const { X402_VERSION, SCHEME, PAYMENT_FLOW, KASPA_SCHEME_ID, SETTLEMENT_POLICY_ID, EVIDENCE_SCHEMA, EVIDENCE_DIGEST_DOMAIN, ASSET_KAS } = require("./constants");
const { FacilitatorRefusal, describe, refuse } = require("./codes");
const { parseFacilitatorRequest } = require("./schema");
const { verifyKasPayment } = require("./verify-kas");
const { verifyTokenPayment, tokenObservationTarget } = require("./verify-token");

function evidenceFor({ requirements, payload, result, claimedAt }) {
  const base = {
    schema: EVIDENCE_SCHEMA,
    status: "CHAIN_VERIFIED",
    settlementPolicy: requirements.policy.id,
    minDepthDaa: requirements.policy.minDepthDaa.toString(),
    network: requirements.network,
    requirementDigest: requirements.requirementDigest,
    requirementId: requirements.requirementId,
    resourceUrl: requirements.resourceUrl,
    transactionId: payload.transactionId,
    outputIndex: payload.outputIndex,
    payTo: requirements.payTo,
    asset: requirements.assetLiteral,
    amount: requirements.amountString,
    covenantId: result.entry.covenantId,
    blockDaaScore: result.entry.blockDaaScore.toString(),
    virtualDaaScore: result.virtualDaaScore.toString(),
    depth: result.depth.toString(),
    node: { serverVersion: result.node.serverVersion, isSynced: true, hasUtxoIndex: true, networkId: result.node.networkId },
    observedAt: result.observedAt
  };
  if (result.token) {
    base.descriptorHash = result.token.descriptorHash;
    base.tokenOwnerScheme = result.token.tokenOwnerScheme;
    base.templateVmHashBlake2b256 = result.token.templateVmHashBlake2b256;
    base.kcc1Corroboration = result.token.kcc1Corroboration;
    base.issuerPowers = result.token.issuerPowers; // verbatim trust properties, DECLARED-ONLY
  }
  if (claimedAt) base.claimedAt = claimedAt;
  base.evidenceDigest = domainDigestHex(EVIDENCE_DIGEST_DOMAIN, base);
  return base;
}

function refusalBody(e, extra = {}) {
  const info = describe(e.code);
  return {
    status: info.cls === "PENDING" ? "PENDING" : info.cls === "RETRY" ? "RETRY" : "REFUSED",
    reasonClass: info.cls,
    reason: e.code,
    explanation: info.text,
    detail: e.detail,
    ...extra
  };
}

class Facilitator {
  /*
   * deps: { chainConfig, bound, assets, claims, node, minDepthDaa,
   *         addressGate(address) → { address, prefix, addressVersion, scriptHex },
   *         addressForScript(scriptHex) → address|null }
   */
  constructor(deps) {
    for (const k of ["chainConfig", "bound", "assets", "claims", "node", "minDepthDaa", "addressGate", "addressForScript"]) {
      if (deps[k] === undefined) throw new Error(`x402-facilitator: dependency ${k} is required`);
    }
    this.deps = deps;
  }

  supported() {
    return {
      kinds: [
        {
          x402Version: X402_VERSION,
          scheme: SCHEME,
          network: this.deps.bound.identifier,
          extra: {
            paymentFlow: PAYMENT_FLOW,
            kaspaScheme: KASPA_SCHEME_ID,
            assets: [...this.deps.assets.list()],
            settlementPolicies: [SETTLEMENT_POLICY_ID],
            minDepthDaa: this.deps.minDepthDaa.toString()
          }
        }
      ],
      extensions: [],
      signers: {}
    };
  }

  _parse(text) {
    return parseFacilitatorRequest(text, {
      bound: this.deps.bound,
      assets: this.deps.assets,
      minDepthDaa: this.deps.minDepthDaa,
      config: this.deps.chainConfig,
      addressGate: (address) => {
        try {
          return this.deps.addressGate(address);
        } catch (e) {
          refuse("ADDRESS_INVALID", String(e && e.message ? e.message : e).slice(0, 160));
        }
      }
    });
  }

  /* Principal constraints supplement — never replace — the deterministic binding. */
  _authorizePrincipal(principal, requirements) {
    if (!principal) return; // unauthenticated callers never reach here (service refuses first)
    if (!principal.networks.includes(requirements.network)) refuse("PRINCIPAL_FORBIDDEN", "network");
    if (principal.allowedPayTo.mode === "list" && !principal.allowedPayTo.addresses.includes(requirements.payTo)) refuse("PRINCIPAL_FORBIDDEN", "destination");
    if (principal.allowedResourceOrigins.mode === "list" && !principal.allowedResourceOrigins.origins.includes(requirements.resourceOrigin)) refuse("PRINCIPAL_FORBIDDEN", "resource origin");
  }

  /* Replay + destination-reuse state (read-only). Returns the identical
   * pair's existing claim (idempotent replay) or null. */
  async _replayState(requirements, payload) {
    const { claims } = this.deps;
    const byDigest = await claims.readByDigest(requirements.requirementDigest);
    if (byDigest) {
      if (byDigest.network === requirements.network && byDigest.transactionId === payload.transactionId && byDigest.outputIndex === payload.outputIndex) return byDigest;
      refuse("REQUIREMENT_ALREADY_SETTLED");
    }
    const byOutpoint = await claims.readByOutpoint(requirements.network, payload.transactionId, payload.outputIndex);
    if (byOutpoint && byOutpoint.pointer.requirementDigest !== requirements.requirementDigest) refuse("PAYMENT_ALREADY_CLAIMED");
    const conflicts = await claims.findDestinationConflicts({
      network: requirements.network,
      payTo: requirements.payTo,
      amount: requirements.amountString,
      validFromDaaScore: requirements.validFrom.toString(),
      validUntilDaaScore: requirements.validUntil.toString(),
      excludeDigest: requirements.requirementDigest
    });
    if (conflicts.length > 0) refuse("REQUIREMENT_DESTINATION_REUSED");
    return null;
  }

  async _observe(addresses, budgetMs) {
    try {
      return await this.deps.node.observe(addresses, { budgetMs });
    } catch (e) {
      if (e instanceof FacilitatorRefusal) throw e;
      // any other failure of the node path is RETRY-classed — never a judgement
      refuse("NODE_UNAVAILABLE", String(e && e.message ? e.message : e).slice(0, 160));
    }
  }

  async _verifyOnChain(requirements, payload) {
    const budgetMs = requirements.maxTimeoutSeconds * 1000;
    if (requirements.asset.kind === ASSET_KAS) {
      const observation = await this._observe([requirements.payTo], budgetMs);
      return verifyKasPayment({ requirements, payload, observation, config: this.deps.chainConfig });
    }
    const target = tokenObservationTarget({ requirements, payload, addressForScript: this.deps.addressForScript });
    const observation = await this._observe([target.address], budgetMs);
    return verifyTokenPayment({ requirements, payload, observation, config: this.deps.chainConfig, observationAddress: target });
  }

  async verify({ text, principal }) {
    let requirements = null;
    let payload = null;
    try {
      ({ requirements, payload } = this._parse(text));
      this._authorizePrincipal(principal, requirements);
      const existing = await this._replayState(requirements, payload);
      const result = await this._verifyOnChain(requirements, payload);
      const common = { requirementDigest: requirements.requirementDigest, claimed: existing !== null };
      if (result.status === "CHAIN_VERIFIED") {
        return { http: 200, body: { isValid: true, payer: payload.payer ?? undefined, extensions: { policyvault: { ...evidenceFor({ requirements, payload, result }), claimed: existing !== null } } } };
      }
      const observed = result.entry ? { blockDaaScore: result.entry.blockDaaScore.toString(), depth: result.depth.toString() } : undefined;
      const e = new FacilitatorRefusal(result.code);
      return { http: 200, body: { isValid: false, invalidReason: result.code, payer: payload.payer ?? undefined, extensions: { policyvault: refusalBody(e, { ...common, status: result.status === "CHAIN_SEEN" ? "PENDING" : result.status, virtualDaaScore: result.virtualDaaScore.toString(), observed }) } } };
    } catch (e) {
      if (!(e instanceof FacilitatorRefusal)) throw e;
      const http = e.cls === "AUTH" ? e.http : e.unparseable ? 400 : e.cls === "RETRY" ? e.http : e.code === "BODY_TOO_LARGE" ? 413 : 200;
      return { http, body: { isValid: false, invalidReason: e.code, extensions: { policyvault: refusalBody(e, requirements ? { requirementDigest: requirements.requirementDigest } : {}) } } };
    }
  }

  async settle({ text, principal }) {
    let requirements = null;
    let payload = null;
    const fail = (e, http) => ({
      http,
      body: {
        success: false,
        errorReason: e.code,
        transaction: payload ? payload.transactionId : undefined,
        network: this.deps.bound.identifier,
        amount: requirements ? requirements.amountString : undefined,
        extensions: { policyvault: refusalBody(e, requirements ? { requirementDigest: requirements.requirementDigest } : {}) }
      }
    });
    try {
      ({ requirements, payload } = this._parse(text));
      this._authorizePrincipal(principal, requirements);
      const existing = await this._replayState(requirements, payload);
      if (existing) {
        // idempotent replay of the identical pair: the SAME stored evidence, no new state
        return { http: 200, body: { success: true, payer: payload.payer ?? undefined, transaction: payload.transactionId, network: requirements.network, amount: requirements.amountString, extensions: { policyvault: { ...existing.evidence, replay: true } } } };
      }
      const result = await this._verifyOnChain(requirements, payload);
      if (result.status !== "CHAIN_VERIFIED") {
        const e = new FacilitatorRefusal(result.code);
        const r = fail(e, 200);
        r.body.extensions.policyvault.status = result.status === "CHAIN_SEEN" ? "PENDING" : result.status;
        r.body.extensions.policyvault.virtualDaaScore = result.virtualDaaScore.toString();
        if (result.entry) r.body.extensions.policyvault.observed = { blockDaaScore: result.entry.blockDaaScore.toString(), depth: result.depth.toString() };
        return r;
      }
      const claimedAt = new Date().toISOString();
      const evidence = evidenceFor({ requirements, payload, result, claimedAt });
      const outcome = await this.deps.claims.createClaim({
        requirementDigest: requirements.requirementDigest,
        network: requirements.network,
        transactionId: payload.transactionId,
        outputIndex: payload.outputIndex,
        payTo: requirements.payTo,
        amount: requirements.amountString,
        asset: requirements.assetLiteral,
        validFromDaaScore: requirements.validFrom.toString(),
        validUntilDaaScore: requirements.validUntil.toString(),
        evidence,
        createdAt: claimedAt
      });
      if (outcome.created) {
        return { http: 200, body: { success: true, payer: payload.payer ?? undefined, transaction: payload.transactionId, network: requirements.network, amount: requirements.amountString, extensions: { policyvault: evidence } } };
      }
      if (outcome.reason === "REPLAY") {
        return { http: 200, body: { success: true, payer: payload.payer ?? undefined, transaction: payload.transactionId, network: requirements.network, amount: requirements.amountString, extensions: { policyvault: { ...outcome.claim.evidence, replay: true } } } };
      }
      return fail(new FacilitatorRefusal(outcome.reason), 200);
    } catch (e) {
      if (!(e instanceof FacilitatorRefusal)) throw e;
      const http = e.cls === "AUTH" ? e.http : e.unparseable ? 400 : e.cls === "RETRY" ? e.http : e.code === "BODY_TOO_LARGE" ? 413 : 200;
      return fail(e, http);
    }
  }
}

module.exports = { Facilitator, evidenceFor, canonicalJsonStringify };
