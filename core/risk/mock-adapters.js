"use strict";

/*
 * Mock risk adapters — test fixtures and reference implementations of
 * the adapter contract (interface.js). Every mock is restrictive-only:
 * a mock that cannot interpret its input returns DENY or REVIEW, never
 * ALLOW (fail closed). Real integrations follow the same shape:
 * docs/postlaunch/risk-adapter-spec.md §6.
 */

const { RISK_ADAPTER_CONTRACT_VERSION, VERDICT_ALLOW, VERDICT_REVIEW, VERDICT_DENY, RiskRefusal } = require("./interface");

/* Strict sompi parsing for mock policy thresholds: BigInt or base-10
 * digit string; JS numbers refuse (floating-point risk). */
const I64_MAX = 2n ** 63n - 1n;
function parseSompiStrict(value, field) {
  let amount;
  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string" && /^\d+$/.test(value)) {
    amount = BigInt(value);
  } else {
    throw new RiskRefusal("INVALID_INTEGER", `${field} must be a BigInt or base-10 digit string`);
  }
  if (amount < 0n || amount > I64_MAX) {
    throw new RiskRefusal("INVALID_INTEGER", `${field} out of range`);
  }
  return amount;
}

function base({ name, capabilities, evaluate, adapterVersion = "1.0.0", timeoutMs }) {
  return {
    name,
    adapterVersion,
    contractVersion: RISK_ADAPTER_CONTRACT_VERSION,
    capabilities,
    evaluate,
    ...(timeoutMs !== undefined ? { timeoutMs } : {})
  };
}

function makeAllowAllAdapter({ name = "mock-allow-all" } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    evaluate: async () => ({ verdict: VERDICT_ALLOW, reasons: [] })
  });
}

function makeDenyAllAdapter({ name = "mock-deny-all", code = "MOCK_DENY", message = "mock adapter denies everything" } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    evaluate: async () => ({ verdict: VERDICT_DENY, reasons: [{ code, message }] })
  });
}

function makeReviewAllAdapter({ name = "mock-review-all", code = "MOCK_REVIEW", message = "mock adapter requests human review" } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    evaluate: async () => ({ verdict: VERDICT_REVIEW, reasons: [{ code, message }] })
  });
}

/*
 * Amount-threshold adapter (fraud-scoring stand-in): DENY above
 * maxSompi, REVIEW above reviewSompi, else ALLOW. A missing or
 * malformed intent amount is DENIED — a screening control that cannot
 * read the amount never allows.
 */
function makeAmountThresholdAdapter({ name = "mock-amount-threshold", maxSompi, reviewSompi } = {}) {
  const max = parseSompiStrict(maxSompi, "maxSompi");
  const review = reviewSompi === undefined ? max : parseSompiStrict(reviewSompi, "reviewSompi");
  if (review > max) {
    throw new RiskRefusal("INVALID_INTEGER", "reviewSompi must be <= maxSompi");
  }
  return base({
    name,
    capabilities: ["fraud-scoring"],
    evaluate: async (intent) => {
      const raw = intent && intent.payAmountSompi;
      if (typeof raw !== "string" || !/^\d+$/.test(raw)) {
        return {
          verdict: VERDICT_DENY,
          reasons: [{ code: "INTENT_AMOUNT_UNREADABLE", message: "intent.payAmountSompi is missing or not a base-10 digit string — failing closed" }]
        };
      }
      const amount = BigInt(raw);
      if (amount > max) {
        return {
          verdict: VERDICT_DENY,
          reasons: [{ code: "AMOUNT_ABOVE_LIMIT", message: `amount ${raw} sompi exceeds the configured limit`, evidence: { limitSompi: max.toString() } }]
        };
      }
      if (amount > review) {
        return {
          verdict: VERDICT_REVIEW,
          reasons: [{ code: "AMOUNT_ABOVE_REVIEW_LINE", message: `amount ${raw} sompi exceeds the review line`, evidence: { reviewSompi: review.toString() } }]
        };
      }
      return { verdict: VERDICT_ALLOW, reasons: [] };
    }
  });
}

/*
 * Recipient screening adapter (sanctions/KYT stand-in): the configured
 * set is the SCREENED-CLEAR list; a recipient outside it gets
 * verdictOnMiss (REVIEW or DENY — ALLOW is not accepted as a miss
 * outcome). Unreadable recipient -> DENY.
 */
function makeRecipientScreeningAdapter({ name = "mock-recipient-screening", clearedRecipients, verdictOnMiss = VERDICT_DENY } = {}) {
  if (!Array.isArray(clearedRecipients)) {
    throw new RiskRefusal("ADAPTER_DEFINITION_INVALID", "clearedRecipients must be an array of x-only hex keys");
  }
  if (verdictOnMiss !== VERDICT_REVIEW && verdictOnMiss !== VERDICT_DENY) {
    throw new RiskRefusal("ADAPTER_DEFINITION_INVALID", "verdictOnMiss must be REVIEW or DENY — a screening miss never allows");
  }
  const cleared = new Set(
    clearedRecipients.map((k) => {
      if (typeof k !== "string" || !/^[0-9a-fA-F]{64}$/.test(k)) {
        throw new RiskRefusal("ADAPTER_DEFINITION_INVALID", "clearedRecipients entries must be 32-byte hex");
      }
      return k.toLowerCase();
    })
  );
  return base({
    name,
    capabilities: ["sanctions", "kyt"],
    evaluate: async (intent) => {
      const raw = intent && intent.recipient;
      if (typeof raw !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw)) {
        return {
          verdict: VERDICT_DENY,
          reasons: [{ code: "INTENT_RECIPIENT_UNREADABLE", message: "intent.recipient is missing or malformed — failing closed" }]
        };
      }
      if (!cleared.has(raw.toLowerCase())) {
        return {
          verdict: verdictOnMiss,
          reasons: [{ code: "RECIPIENT_NOT_SCREENED_CLEAR", message: "recipient is not on the screened-clear list", evidence: { recipient: raw.toLowerCase() } }]
        };
      }
      return { verdict: VERDICT_ALLOW, reasons: [] };
    }
  });
}

function makeThrowingAdapter({ name = "mock-throwing", message = "mock adapter failure" } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    evaluate: async () => {
      throw new Error(message);
    }
  });
}

function makeSyncThrowingAdapter({ name = "mock-sync-throwing", message = "mock synchronous failure" } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    evaluate: () => {
      throw new Error(message);
    }
  });
}

/* Never settles: exercises the timeout path. */
function makeHangingAdapter({ name = "mock-hanging", timeoutMs } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    evaluate: () => new Promise(() => {})
  });
}

/* Returns whatever it is configured with — for unknown-verdict tests. */
function makeMalformedVerdictAdapter({ name = "mock-malformed", result } = {}) {
  return base({
    name,
    capabilities: ["custom-policy"],
    evaluate: async () => result
  });
}

function makeSlowAdapter({ name = "mock-slow", delayMs = 50, verdict = VERDICT_ALLOW, timeoutMs } = {}) {
  const reasons = verdict === VERDICT_ALLOW ? [] : [{ code: "MOCK_SLOW", message: "slow adapter verdict" }];
  return base({
    name,
    capabilities: ["custom-policy"],
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    evaluate: () => new Promise((resolve) => setTimeout(() => resolve({ verdict, reasons }), delayMs))
  });
}

module.exports = {
  makeAllowAllAdapter,
  makeDenyAllAdapter,
  makeReviewAllAdapter,
  makeAmountThresholdAdapter,
  makeRecipientScreeningAdapter,
  makeThrowingAdapter,
  makeSyncThrowingAdapter,
  makeHangingAdapter,
  makeMalformedVerdictAdapter,
  makeSlowAdapter
};
