"use strict";

/*
 * AP2 mandate-constraint evaluation — RESTRICTIVE-ONLY BY CONSTRUCTION
 * (ap2-adapter-spec.md §3.5). The maximum power of this evaluator,
 * correct or hostile, is DENY or REVIEW; there is no code path that
 * produces a permission (its ALLOW means only "no constraint objected" —
 * the full covenant/policy/risk pipeline still runs afterwards, and the
 * floor never moves: a mandate looser than the covenant's agent policy
 * changes nothing; the covenant wins silently and absolutely).
 *
 * Composition is deny-wins. Unknown constraint types DENY
 * (AP2_CONSTRAINT_UNKNOWN); unparseable values DENY
 * (AP2_CONSTRAINT_UNREADABLE) — an unreadable control never allows.
 *
 * DEPLOYMENT NOTE (interim decision, recorded in the evidence doc): the
 * spec's target home for these rules is a `policyvault-risk-adapter/1`
 * adapter registered in the SERVER's org risk configuration. Registering
 * one requires a server-side configuration change outside this
 * integration's file ownership, so v1 evaluates the same matrix
 * ADAPTER-SIDE, BEFORE simulate — strictly restrictive-only (it can only
 * refuse or hold; it cannot skip any downstream gate). A REVIEW verdict
 * is handled FAIL-CLOSED in v1 (rejection with the REVIEW code) because
 * an adapter-side hold would have no releasable evaluation record; the
 * releasable-REVIEW path returns when the server-side risk adapter is
 * registered as a separately reviewed change.
 *
 * The constraint VALUE SHAPES below are this implementation's interim
 * reading of upstream schemas that AP2 does not fully publish; every
 * shape is refusal-biased and recorded as interim in the evidence note.
 */

const { Ap2Refusal } = require("./codes");

const VERDICT_RANK = Object.freeze({ ALLOW: 0, REVIEW: 1, DENY: 2 });

function isPlainObject(v) {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

function closedKeys(obj, allowed) {
  return isPlainObject(obj) && Object.keys(obj).every((k) => allowed.includes(k));
}

function safeInt(v) {
  return typeof v === "number" && Number.isSafeInteger(v);
}

/* Extract an id set from {allowed: [...]} where entries are strings or
 * {id: string, ...}. Anything else is unreadable. */
function idSetOf(value, extraEntryKeys) {
  if (!closedKeys(value, ["type", "allowed"]) || !Array.isArray(value.allowed) || value.allowed.length === 0) return null;
  const out = new Set();
  for (const entry of value.allowed) {
    if (typeof entry === "string" && entry.length > 0 && entry.length <= 256) {
      out.add(entry);
      continue;
    }
    if (isPlainObject(entry) && typeof entry.id === "string" && entry.id.length > 0 && Object.keys(entry).every((k) => ["id", ...extraEntryKeys].includes(k))) {
      out.add(entry.id);
      continue;
    }
    return null;
  }
  return out;
}

/*
 * Evaluate every extracted constraint against the normalized proposal.
 *
 * context: {
 *   payAmountSompi (canonical digits), payeeId, instrumentHandle,
 *   transactionId,
 *   nowSeconds,
 *   accounting: { consumedSompi (BigInt-string), occurrenceCount (int) }
 *     — prior attempts for the SAME open mandate (settled + in-flight;
 *       refused/expired/failed attempts do not consume)
 * }
 * Returns { decision, evaluated: [{type, verdict, code|null}], codes }.
 */
function evaluateConstraints(constraints, context) {
  if (!Array.isArray(constraints)) throw new Ap2Refusal("AP2_CONSTRAINT_UNREADABLE", "constraints must be an array");
  const evaluated = [];
  const codes = [];
  let decision = "ALLOW";

  const raise = (verdict, type, code) => {
    evaluated.push({ type, verdict, code });
    if (code) codes.push(code);
    if (VERDICT_RANK[verdict] > VERDICT_RANK[decision]) decision = verdict;
  };
  const pass = (type) => evaluated.push({ type, verdict: "ALLOW", code: null });

  const amount = BigInt(context.payAmountSompi);

  for (const { type, value } of constraints) {
    try {
      if (type === null) {
        raise("DENY", null, "AP2_CONSTRAINT_UNREADABLE");
        continue;
      }
      switch (type) {
        case "payment.amount_range": {
          if (!closedKeys(value, ["type", "min", "max"]) || (value.min === undefined && value.max === undefined) || (value.min !== undefined && !safeInt(value.min)) || (value.max !== undefined && !safeInt(value.max))) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          const min = value.min !== undefined ? BigInt(value.min) : null;
          const max = value.max !== undefined ? BigInt(value.max) : null;
          if ((min !== null && amount < min) || (max !== null && amount > max)) raise("DENY", type, "AP2_AMOUNT_OUT_OF_RANGE");
          else pass(type);
          break;
        }
        case "payment.budget": {
          if (!closedKeys(value, ["type", "amount", "currency"]) || !safeInt(value.amount) || value.amount < 1 || typeof value.currency !== "string") {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          if (value.currency !== context.currencyLiteral) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE"); // a budget in a currency we cannot compare never allows
            break;
          }
          const consumed = BigInt(context.accounting && /^(0|[1-9][0-9]*)$/.test(context.accounting.consumedSompi ?? "") ? context.accounting.consumedSompi : "0");
          if (consumed + amount > BigInt(value.amount)) raise("DENY", type, "AP2_MANDATE_BUDGET_EXCEEDED");
          else pass(type);
          break;
        }
        case "payment.allowed_payees": {
          const ids = idSetOf(value, ["name", "website"]);
          if (!ids) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          if (!ids.has(context.payeeId)) raise("DENY", type, "AP2_PAYEE_NOT_IN_MANDATE");
          else pass(type);
          break;
        }
        case "payment.allowed_payment_instruments": {
          const ids = idSetOf(value, ["type", "description"]);
          if (!ids) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          if (!ids.has(context.instrumentHandle)) raise("DENY", type, "AP2_INSTRUMENT_NOT_IN_MANDATE");
          else pass(type);
          break;
        }
        case "payment.allowed_pisps": {
          // PolicyVault is never a PISP; a mandate that requires routing
          // through one is unsatisfiable here.
          raise("DENY", type, "AP2_PISP_UNSUPPORTED");
          break;
        }
        case "payment.agent_recurrence": {
          if (!closedKeys(value, ["type", "max_occurrences"]) || !safeInt(value.max_occurrences) || value.max_occurrences < 1) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          const count = context.accounting && safeInt(context.accounting.occurrenceCount) ? context.accounting.occurrenceCount : 0;
          if (count + 1 > value.max_occurrences) raise("DENY", type, "AP2_RECURRENCE_EXCEEDED");
          else pass(type);
          break;
        }
        case "payment.execution_date": {
          if (!closedKeys(value, ["type", "not_before", "not_after"]) || (value.not_before === undefined && value.not_after === undefined) || (value.not_before !== undefined && !safeInt(value.not_before)) || (value.not_after !== undefined && !safeInt(value.not_after))) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          const now = context.nowSeconds;
          if ((value.not_before !== undefined && now < value.not_before) || (value.not_after !== undefined && now > value.not_after)) {
            raise("DENY", type, "AP2_EXECUTION_WINDOW");
          } else pass(type);
          break;
        }
        case "payment.reference": {
          if (!closedKeys(value, ["type", "conditional_transaction_id"]) || typeof value.conditional_transaction_id !== "string") {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          if (value.conditional_transaction_id !== context.transactionId) raise("DENY", type, "AP2_REFERENCE_MISMATCH");
          else pass(type);
          break;
        }
        case "checkout.allowed_merchants": {
          const ids = idSetOf(value, ["name", "website"]);
          if (!ids) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          if (!ids.has(context.payeeId)) raise("DENY", type, "AP2_MERCHANT_NOT_ALLOWED");
          else pass(type);
          break;
        }
        case "checkout.line_items": {
          // Line items are DESCRIPTIVE (what was bought, never what may
          // be paid — their price/currency NEVER become payAmountSompi).
          // Readable items whose totals disagree with payment_amount are
          // a human question: REVIEW. Unreadable structure: DENY.
          if (!closedKeys(value, ["type", "items"]) || !Array.isArray(value.items)) {
            raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
            break;
          }
          let total = 0n;
          let comparable = true;
          let readable = true;
          for (const item of value.items) {
            if (!isPlainObject(item)) {
              readable = false;
              break;
            }
            if (item.price === undefined && item.currency === undefined) continue; // id/title-only requirement rows carry no money data
            if (!safeInt(item.price) || item.price < 0 || typeof item.currency !== "string") {
              readable = false;
              break;
            }
            if (item.currency !== context.currencyLiteral) {
              comparable = false;
              continue;
            }
            total += BigInt(item.price);
          }
          if (!readable) raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE");
          else if (!comparable || (total > 0n && total !== amount)) raise("REVIEW", type, "AP2_LINE_ITEMS_MISMATCH");
          else pass(type);
          break;
        }
        default:
          raise("DENY", type, "AP2_CONSTRAINT_UNKNOWN");
      }
    } catch {
      raise("DENY", type, "AP2_CONSTRAINT_UNREADABLE"); // an evaluator throw can never resolve permissive
    }
  }

  return { decision, evaluated, codes };
}

module.exports = { evaluateConstraints, VERDICT_RANK };
