"use strict";

/*
 * Native KAS verification (spec §7.1). Pure given an observation: the
 * caller (facilitator.js) performs the node observation of `payTo`
 * through NodeSession and hands the entries here. Returns a verification
 * result — never writes state.
 */

const { refuse } = require("./codes");
const { classifyDepth, unobservedDisposition } = require("./policy");
const { parseTransactionCarriage } = require("./carriage");

function findEntry(entries, transactionId, outputIndex) {
  return entries.find((e) => e.transactionId === transactionId && e.index === outputIndex) ?? null;
}

/*
 * verifyKasPayment({ requirements, payload, observation, config })
 *   → { status: "CHAIN_VERIFIED" | "CHAIN_SEEN" | "PENDING" | "REFUSED",
 *       code?, entry?, depth?, node, virtualDaaScore, observedAt }
 */
function verifyKasPayment({ requirements, payload, observation, config }) {
  const { policy, payTo, destination, amount, validFrom, validUntil } = requirements;

  // step 3: optional transaction carriage — recomputed txid must equal the presented one
  if (payload.transactionHex !== null) {
    const view = parseTransactionCarriage(config, payload.transactionHex);
    if (view.transactionId !== payload.transactionId) refuse("TXID_MISMATCH");
  }

  // step 4: exact outpoint in the UTXO index of payTo
  const entries = observation.entries.get(payTo) ?? [];
  const entry = findEntry(entries, payload.transactionId, payload.outputIndex);
  if (!entry) {
    const code = unobservedDisposition({ virtualDaaScore: observation.virtualDaaScore, validUntil, minDepthDaa: policy.minDepthDaa });
    return { status: code === "REQUIREMENT_EXPIRED" ? "REFUSED" : "PENDING", code, node: observation.node, virtualDaaScore: observation.virtualDaaScore, observedAt: observation.observedAt };
  }

  // step 5: exact match at the outpoint — a plain KAS output paying exactly `amount` to exactly `payTo`
  if (entry.scriptPublicKeyHex !== destination.scriptHex) refuse("OUTPUT_MISMATCH", "script public key differs from payTo");
  if (entry.amount !== amount) refuse("OUTPUT_MISMATCH", `amount ${entry.amount} != required ${amount}`);
  if (entry.covenantId !== null) refuse("OUTPUT_MISMATCH", "a covenant-carrying output is not a plain KAS payment");
  if (entry.isCoinbase !== false) refuse("OUTPUT_MISMATCH", "coinbase output");

  // step 6: inclusion inside the validity window
  if (entry.blockDaaScore < validFrom || entry.blockDaaScore > validUntil) refuse("PAYMENT_OUTSIDE_WINDOW", `inclusion DAA ${entry.blockDaaScore} outside [${validFrom}, ${validUntil}]`);

  // step 7: settlement depth
  const { depth, status } = classifyDepth({ virtualDaaScore: observation.virtualDaaScore, blockDaaScore: entry.blockDaaScore, minDepthDaa: policy.minDepthDaa });
  return { status, code: status === "CHAIN_SEEN" ? "PAYMENT_PENDING_DEPTH" : null, entry, depth, node: observation.node, virtualDaaScore: observation.virtualDaaScore, observedAt: observation.observedAt };
}

module.exports = { verifyKasPayment, findEntry };
