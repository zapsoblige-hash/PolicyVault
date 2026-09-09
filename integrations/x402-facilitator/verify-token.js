"use strict";

/*
 * Token payment verification — FROZEN v0.5 semantics (spec §7.2, §17.2–4).
 * BOTH bindings are required; covenant ownership alone is never sufficient:
 *   Binding 1 (WHO):   the observed UTXO entry carries covenantId ==
 *                      descriptor.tokenCovenantId (consensus-tracked lineage).
 *   Binding 2 (WHICH): the payer-supplied redeem hashes to the entry's P2SH
 *                      script, corroborates an accepted template (geometry +
 *                      in-VM hash + standardness), and its kcc20-state/1
 *                      owner == payTo's owner encoding with amount == required.
 * Plus an independent conservation check over the supplied transaction
 * (consistency data — it can only refuse, never accept; §17.2).
 * No x402-specific token parser exists: every token operation is a call
 * into core/assets (the same code the v0.5 SDK and browser bundle use).
 */

const assets = require("../../core/assets");
const { refuse } = require("./codes");
const { classifyDepth, unobservedDisposition } = require("./policy");
const { parseTransactionCarriage } = require("./carriage");
const { findEntry } = require("./verify-kas");

const OWNER_P2PK = assets.kcc20.OWNER_SCHEMES.P2PK;
const OWNER_P2SH = assets.kcc20.OWNER_SCHEMES.P2SH;

/* payTo → kcc20-state/1 owner encoding, derived from its canonical script:
 * P2PK `20<32 x-only>ac` → scheme 0x00; P2SH `aa20<32 hash>87` → scheme 0x01. */
function ownerEncodingOf(destination) {
  const s = destination.scriptHex;
  if (destination.addressVersion === "PubKey" && s.length === 68 && s.startsWith("20") && s.endsWith("ac")) return { scheme: OWNER_P2PK, identifier: s.slice(2, 66) };
  if (destination.addressVersion === "ScriptHash" && s.length === 70 && s.startsWith("aa20") && s.endsWith("87")) return { scheme: OWNER_P2SH, identifier: s.slice(4, 68) };
  refuse("ADDRESS_INVALID", "payTo has no kcc20-state/1 owner encoding");
}

/* Redeem hex → verified template view, or null when it matches no accepted template. */
function familyRedeemView(descriptor, redeemHex) {
  try {
    return assets.verifyTokenInputRedeem({ descriptor, redeemHex });
  } catch (e) {
    if (e && (e.code === "TEMPLATE_HASH_MISMATCH" || e.code === "KCC20_GEOMETRY_MISMATCH" || e.code === "KCC20_MALFORMED")) return null;
    if (e && e.code === "KCC20_UNKNOWN_OWNER_SCHEME") refuse("TOKEN_OWNER_MISMATCH", e.message);
    if (e && e.code === "KCC20_MALFORMED_STATE") refuse("TOKEN_TEMPLATE_MISMATCH", e.message);
    throw e;
  }
}

function verifyTokenPayment({ requirements, payload, observation, config, observationAddress }) {
  const { policy, destination, amount, validFrom, validUntil, asset } = requirements;
  const descriptor = asset.descriptor;

  // 1–3: carriage is REQUIRED for tokens; txid recomputed through the engine
  if (payload.transactionHex === null || payload.outputRedeems === null) refuse("TOKEN_REDEEM_REQUIRED");
  const tx = parseTransactionCarriage(config, payload.transactionHex);
  if (tx.transactionId !== payload.transactionId) refuse("TXID_MISMATCH");
  if (payload.outputIndex >= tx.outputs.length) refuse("OUTPUT_MISMATCH", "outputIndex beyond the supplied transaction's outputs");

  // Binding 2 (part 1): the paid output's redeem must be supplied and hash to that output's script
  const redeemHex = payload.outputRedeems.get(payload.outputIndex);
  if (redeemHex === undefined) refuse("TOKEN_REDEEM_REQUIRED", `no redeem supplied for output ${payload.outputIndex}`);
  const paid = familyRedeemView(descriptor, redeemHex);
  if (!paid) refuse("TOKEN_TEMPLATE_MISMATCH", "the redeem of the paid output matches no accepted template");
  if (tx.outputs[payload.outputIndex].scriptPublicKeyHex !== paid.p2shSpkHex) refuse("TOKEN_TEMPLATE_MISMATCH", "the supplied redeem does not hash to the paid output's script");
  let corroboration;
  try {
    corroboration = assets.corroborateTemplate({ descriptor, templateIndex: paid.templateIndex, prefixHex: paid.prefixHex, suffixHex: paid.suffixHex });
  } catch (e) {
    refuse("TOKEN_TEMPLATE_MISMATCH", `${e.code ?? "template"}: ${e.message}`);
  }
  if (observationAddress !== undefined && observationAddress !== null && paid.p2shSpkHex !== observationAddress.scriptHex) refuse("TOKEN_TEMPLATE_MISMATCH", "observation address does not match the redeem");

  // 4–5: observe the exact outpoint at the token program's P2SH address
  const entries = observation.entries.get(observationAddress.address) ?? [];
  const entry = findEntry(entries, payload.transactionId, payload.outputIndex);
  if (!entry) {
    const code = unobservedDisposition({ virtualDaaScore: observation.virtualDaaScore, validUntil, minDepthDaa: policy.minDepthDaa });
    return { status: code === "REQUIREMENT_EXPIRED" ? "REFUSED" : "PENDING", code, node: observation.node, virtualDaaScore: observation.virtualDaaScore, observedAt: observation.observedAt };
  }
  if (entry.scriptPublicKeyHex !== paid.p2shSpkHex) refuse("TOKEN_TEMPLATE_MISMATCH", "observed script differs from the supplied redeem's P2SH script");
  if (entry.isCoinbase !== false) refuse("OUTPUT_MISMATCH", "coinbase output");
  // Binding 1 (WHO): consensus covenant lineage
  if (entry.covenantId !== descriptor.tokenCovenantId) refuse("UNSUPPORTED_TOKEN_PROGRAM", `observed covenant id ${entry.covenantId ?? "null"} is not the descriptor's token family`);

  // 6: decoded owner + amount
  const owner = ownerEncodingOf(destination);
  if (paid.state.identifierType !== owner.scheme || paid.state.ownerIdentifier !== owner.identifier) refuse("TOKEN_OWNER_MISMATCH");
  if (paid.state.isMinter !== false) refuse("UNSUPPORTED_TOKEN_PROGRAM", "minter positions are not payments");
  if (paid.state.amount !== amount) refuse("OUTPUT_MISMATCH", `token amount ${paid.state.amount} != required ${amount}`);

  // 7: independent conservation over the supplied transaction (consistency; can only refuse)
  let sumIn = 0n;
  for (const input of tx.inputs) {
    let redeem;
    try {
      redeem = assets.redeemFromSignatureScript(input.signatureScriptHex);
    } catch {
      continue; // not a P2SH spend with a data push — not a family input
    }
    const view = familyRedeemView(descriptor, redeem);
    if (!view) continue;
    if (input.suppliedUtxoScriptPublicKeyHex !== null && input.suppliedUtxoScriptPublicKeyHex !== view.p2shSpkHex) refuse("TOKEN_CONSERVATION_FAILED", "a family input's supplied UTXO script differs from its revealed redeem");
    sumIn += view.state.amount;
  }
  let sumOut = 0n;
  for (const output of tx.outputs) {
    const supplied = payload.outputRedeems.get(output.index);
    if (supplied !== undefined) {
      const view = familyRedeemView(descriptor, supplied);
      if (!view) refuse("TOKEN_TEMPLATE_MISMATCH", `outputRedeems[${output.index}] matches no accepted template`);
      if (view.p2shSpkHex !== output.scriptPublicKeyHex) refuse("TOKEN_CONSERVATION_FAILED", `outputRedeems[${output.index}] does not hash to that output's script`);
      sumOut += view.state.amount;
    } else if (output.covenantId === descriptor.tokenCovenantId) {
      refuse("TOKEN_CONSERVATION_FAILED", `family output ${output.index} has no supplied redeem`);
    }
  }
  if (sumIn !== sumOut) refuse("TOKEN_CONSERVATION_FAILED", `Σ inputs ${sumIn} != Σ outputs ${sumOut}`);

  // 9: window + depth
  if (entry.blockDaaScore < validFrom || entry.blockDaaScore > validUntil) refuse("PAYMENT_OUTSIDE_WINDOW", `inclusion DAA ${entry.blockDaaScore} outside [${validFrom}, ${validUntil}]`);
  const { depth, status } = classifyDepth({ virtualDaaScore: observation.virtualDaaScore, blockDaaScore: entry.blockDaaScore, minDepthDaa: policy.minDepthDaa });
  return {
    status,
    code: status === "CHAIN_SEEN" ? "PAYMENT_PENDING_DEPTH" : null,
    entry,
    depth,
    node: observation.node,
    virtualDaaScore: observation.virtualDaaScore,
    observedAt: observation.observedAt,
    token: {
      descriptorHash: asset.descriptorHash,
      tokenOwnerScheme: `0x${owner.scheme.toString(16).padStart(2, "0")}`,
      templateIndex: paid.templateIndex,
      templateVmHashBlake2b256: paid.templateVmHashBlake2b256,
      kcc1Corroboration: corroboration.kcc1Corroboration,
      conservation: { inputs: sumIn.toString(), outputs: sumOut.toString() },
      issuerPowers: { ...descriptor.issuerPowers }
    }
  };
}

/* The observation address for a token payment: the P2SH address of the
 * supplied redeem for outputIndex (spec §17.3). Pure; refuses when the
 * carriage is missing or the redeem matches no template. */
function tokenObservationTarget({ requirements, payload, addressForScript }) {
  if (payload.transactionHex === null || payload.outputRedeems === null) refuse("TOKEN_REDEEM_REQUIRED");
  const redeemHex = payload.outputRedeems.get(payload.outputIndex);
  if (redeemHex === undefined) refuse("TOKEN_REDEEM_REQUIRED", `no redeem supplied for output ${payload.outputIndex}`);
  const view = familyRedeemView(requirements.asset.descriptor, redeemHex);
  if (!view) refuse("TOKEN_TEMPLATE_MISMATCH", "the redeem of the paid output matches no accepted template");
  const address = addressForScript(view.p2shSpkHex);
  if (!address) refuse("TOKEN_TEMPLATE_MISMATCH", "the redeem's P2SH script has no address form");
  return Object.freeze({ address, scriptHex: view.p2shSpkHex });
}

module.exports = { verifyTokenPayment, tokenObservationTarget, ownerEncodingOf };
