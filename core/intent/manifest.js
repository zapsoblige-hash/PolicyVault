"use strict";

/*
 * PolicyVault Transaction Intent Manifest v1 — schema + validation + build.
 *
 * A manifest is a deterministic, portable JSON description of what ONE
 * proposed PolicyVault transaction ACTUALLY does: identity, decoded
 * transaction facts, state before/after, exact value accounting, limits,
 * approvals, allowlist evaluation, and the explicit policy-mutation diff.
 * The companion verifier (verify.js) compares a manifest against the
 * structured requested intent and the structured decoded transaction and
 * emits its verified statement ONLY when every fail-closed detector passes.
 *
 * Field shapes MIRROR the real SDK structures (never invented):
 *   - state tuple           -> sdk/src/vault-state-v4.js  stateToJsonV4
 *   - agent policy leaf     -> sdk/src/agent-merkle-v4.js normalizeAgentPolicyV4
 *   - decoded transaction   -> sdk/src/frozen-tx-v3.js    canonicalFrozenTxJson
 *   - accounting (11 keys)  -> sdk/src/vault-builders-v4.js build.accounting
 *   - action/role table     -> sdk/src/wallet-requests-v4.js ROLE_BY_ACTION
 *   - nonce + mutable-field -> sdk/src/vault-transitions-v4.js
 *   - amount discipline     -> sdk/src/amounts.js (integer sompi only)
 *
 * HARD RULES (fail closed, never a default route):
 *   - unknown manifest versions, intent versions, covenant versions, and
 *     actions are refused with a specific code;
 *   - every schema is CLOSED: unknown keys are refused (a hidden field is
 *     a hidden effect);
 *   - all consensus/accounting quantities are CANONICAL base-10 digit
 *     strings ("0" or no leading zero) parsed to BigInt — JS numbers are
 *     refused on every amount path (one value = one encoding = one hash);
 *   - hex is exact-width lowercase only (one value = one encoding);
 *   - the manifest hash is representation-independent (canonical.js).
 *
 * Portable shared core: pure CommonJS, zero external deps, no SDK/server
 * imports.
 */

const { canonicalJsonStringify, computeManifestHashV1 } = require("./canonical");

const MANIFEST_VERSION_1 = "policyvault-intent-manifest/1";
const REQUESTED_INTENT_VERSION_1 = "policyvault-requested-intent/1";

/* Covenant versions manifest v1 can DESCRIBE AND VERIFY (the v0.4 family,
 * mirroring sdk/src/vault-state-v4.js V4_ABIS). Anything else — unknown OR
 * simply not covered by manifest v1 (e.g. policyvault-0.3) — is refused;
 * a future manifest version extends coverage additively. */
const SUPPORTED_COVENANT_VERSIONS = Object.freeze(["policyvault-0.4", "policyvault-0.4.1"]);

/* Integer sompi domain — mirrors sdk/src/amounts.js. */
const SOMPI_PER_KAS = 100000000n;
const MAX_SOMPI = 29000000000n * SOMPI_PER_KAS;

const MAX_APPROVERS = 10;
const APPROVER_SENTINEL = "00".repeat(32);
const NATIVE_SUBNETWORK = "00".repeat(20);
const MAX_POLICY_NONCE = 1000000000n; // vault-state-v4 policyNonce bound
const MAX_PERIODS_ELAPSED = 1000n; // covenant: require(periodsElapsed <= 1000)

/*
 * Per-action metadata — mirrors ROLE_BY_ACTION (wallet-requests-v4.js),
 * the per-entrypoint mutable-field matrix and the exact policyNonce rule
 * (vault-transitions-v4.js), plus genesis. Unknown actions FAIL CLOSED.
 *   nonce "preserve":  agentSpend, ownerTopUp, ownerTopUpReserve,
 *                      ownerPause, ownerUnpause
 *   nonce "increment": ownerSetAgentRoot, ownerSetApprovers
 */
const ACTIONS = Object.freeze({
  agentSpend: Object.freeze({ role: "agent", genesis: false, terminal: false, mutable: Object.freeze(["protectedValue", "feeReserve", "agentRoot"]), nonce: "preserve" }),
  ownerSetAgentRoot: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["agentRoot"]), nonce: "increment" }),
  ownerSetApprovers: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["approverSlots", "approvalM"]), nonce: "increment" }),
  ownerTopUp: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["protectedValue"]), nonce: "preserve" }),
  ownerTopUpReserve: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["feeReserve"]), nonce: "preserve" }),
  ownerPause: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["paused"]), nonce: "preserve" }),
  ownerUnpause: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["paused"]), nonce: "preserve" }),
  ownerRecover: Object.freeze({ role: "owner", genesis: false, terminal: true, mutable: Object.freeze([]), nonce: null }),
  createVault: Object.freeze({ role: "owner", genesis: true, terminal: false, mutable: Object.freeze([]), nonce: null })
});

/* High-level owner agent-lifecycle actions map to ownerSetAgentRoot at the
 * SDK layer (wallet-requests-v4.js planV4); the manifest records both. */
const HIGH_LEVEL_TO_SDK = Object.freeze({
  addAgent: "ownerSetAgentRoot",
  removeAgent: "ownerSetAgentRoot",
  rotateAgent: "ownerSetAgentRoot",
  rePolicyAgent: "ownerSetAgentRoot"
});

/* v0.4-family state tuple field names in canonical order (stateToJsonV4). */
const STATE_FIELDS = Object.freeze(["protectedValue", "feeReserve", "paused", "agentRoot", "approverSlots", "approvalM", "policyNonce"]);

/* v0.4 agent policy leaf field names (agent-merkle-v4.js). */
const AGENT_POLICY_FIELDS = Object.freeze([
  "agentPk",
  "maxPerSpend",
  "periodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "periodSpent",
  "approvalThreshold",
  "agentMaxFeePerTx",
  "agentRecipientRoot"
]);

/* Builder accounting field names (vault-builders-v4.js build.accounting). */
const ACCOUNTING_FIELDS = Object.freeze([
  "predecessorProtected",
  "predecessorFeeReserve",
  "payAmount",
  "reserveConsumed",
  "externalIn",
  "externalOut",
  "fee",
  "successorProtected",
  "successorFeeReserve",
  "successorTotal",
  "terminalPayout"
]);

const INPUT_KINDS = Object.freeze(["covenant", "external"]);
const OUTPUT_KINDS = Object.freeze(["successor", "payment", "change", "recoverPayout", "genesisVault", "agentFuel"]);

/* ------------------------------------------------------------------ */
/* refusal + guards                                                    */
/* ------------------------------------------------------------------ */

function refuse(code, message) {
  const e = new Error(`intent-manifest: ${message}`);
  e.code = code;
  throw e;
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function requireObject(v, path) {
  if (!isPlainObject(v)) refuse("SCHEMA_INVALID", `${path} must be a plain object`);
  return v;
}

/* CLOSED schema: exactly these keys — unknown keys are hidden effects. */
function requireExactKeys(obj, keys, path) {
  requireObject(obj, path);
  for (const k of Object.keys(obj)) {
    if (!keys.includes(k)) refuse("SCHEMA_INVALID", `${path} carries unknown key ${JSON.stringify(k)} — failing closed`);
  }
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) refuse("SCHEMA_INVALID", `${path}.${k} is required`);
  }
  return obj;
}

const CANONICAL_DIGITS_RE = /^(0|[1-9][0-9]*)$/;

/*
 * Canonical integer-sompi guard (STRICTER than sdk/src/amounts.js
 * parseSompi, which accepts leading zeros): a manifest quantity must have
 * exactly one encoding, because the manifest hash is a function of the
 * encoding of values. Rejects everything that is not a canonical base-10
 * digit string: numbers (floating-point risk: NaN/Infinity/negatives/
 * unsafe integers all arrive as numbers), BigInt (not JSON), signs,
 * decimals, exponents, whitespace, leading zeros, non-ASCII digits.
 */
function parseAmount(value, field, { min = 0n, max = MAX_SOMPI } = {}) {
  if (typeof value !== "string") {
    refuse("VALUE_INVALID", `${field} must be a canonical base-10 digit string, got ${typeof value}`);
  }
  if (!CANONICAL_DIGITS_RE.test(value)) {
    refuse("VALUE_INVALID", `${field} is not a canonical base-10 digit string: ${JSON.stringify(value)}`);
  }
  const amount = BigInt(value);
  if (amount < min) refuse("VALUE_INVALID", `${field} must be >= ${min}`);
  if (amount > max) refuse("VALUE_INVALID", `${field} exceeds the maximum representable value (${max})`);
  return amount;
}

function parsePositiveAmount(value, field, opts = {}) {
  return parseAmount(value, field, { ...opts, min: 1n });
}

/* Structural JS integers (indexes, computeBudget, script version) — the
 * only place JS numbers are accepted, mirroring frozen-tx-v3.js. */
function requireInt(value, field, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    refuse("VALUE_INVALID", `${field} must be a safe integer, got ${typeof value === "number" ? String(value) : typeof value}`);
  }
  if (value < min || value > max) refuse("VALUE_INVALID", `${field} out of range [${min}, ${max}]`);
  return value;
}

/* Exact-width LOWERCASE hex only — one value, one encoding, one hash.
 * (sdk normalizeHex lowercases; a manifest must already be canonical.) */
function requireHex(value, bytes, field) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    refuse("VALUE_INVALID", `${field} must be ${bytes}-byte lowercase hex`);
  }
  return value;
}

function requireEvenHex(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
    refuse("VALUE_INVALID", `${field} must be non-empty even-length lowercase hex`);
  }
  return value;
}

function requireBool(value, field) {
  if (typeof value !== "boolean") refuse("VALUE_INVALID", `${field} must be a boolean`);
  return value;
}

function requireNetworkId(value, field) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value)) {
    refuse("VALUE_INVALID", `${field} must be a lowercase network id (e.g. "mainnet", "testnet-10")`);
  }
  return value;
}

function requireCode(value, field) {
  if (typeof value !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(value)) {
    refuse("VALUE_INVALID", `${field} must be an UPPER_SNAKE code`);
  }
  return value;
}

function requireDetail(value, field) {
  if (typeof value !== "string" || value.length > 2000) {
    refuse("VALUE_INVALID", `${field} must be a string of at most 2000 characters`);
  }
  return value;
}

/* Kaspa standard P2PK script for an x-only key: OP_DATA_32 <key>
 * OP_CHECKSIG — mirrors sdk p2pkScriptHex (approval-package-v3.js). */
function p2pkScriptHex(xOnly) {
  return `20${xOnly}ac`;
}

/* ------------------------------------------------------------------ */
/* component schemas                                                   */
/* ------------------------------------------------------------------ */

/* v0.4-family state tuple — exact stateToJsonV4 shape. Returns a parsed
 * BigInt view; the input document is left untouched. */
function validateStateShape(state, path) {
  requireExactKeys(state, STATE_FIELDS, path);
  const protectedValue = parsePositiveAmount(state.protectedValue, `${path}.protectedValue`);
  const feeReserve = parseAmount(state.feeReserve, `${path}.feeReserve`);
  const paused = parseAmount(state.paused, `${path}.paused`, { max: 1n });
  const agentRoot = requireHex(state.agentRoot, 32, `${path}.agentRoot`);
  if (!Array.isArray(state.approverSlots) || state.approverSlots.length !== MAX_APPROVERS) {
    refuse("SCHEMA_INVALID", `${path}.approverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
  }
  const seen = new Set();
  let activeCount = 0;
  state.approverSlots.forEach((k, i) => {
    const key = requireHex(k, 32, `${path}.approverSlots[${i}]`);
    if (key !== APPROVER_SENTINEL) {
      if (seen.has(key)) refuse("SCHEMA_INVALID", `${path}.approverSlots[${i}] duplicates an earlier active approver key`);
      seen.add(key);
      activeCount += 1;
    }
  });
  const approvalM = parseAmount(state.approvalM, `${path}.approvalM`, { max: BigInt(MAX_APPROVERS) });
  if (activeCount === 0) {
    if (approvalM !== 0n) refuse("SCHEMA_INVALID", `${path}.approvalM must be 0 when there are no active approvers`);
  } else {
    if (approvalM < 1n) refuse("SCHEMA_INVALID", `${path}.approvalM must be >= 1 when approvers are configured`);
    if (approvalM > BigInt(activeCount)) refuse("SCHEMA_INVALID", `${path}.approvalM exceeds the active approver count (${activeCount})`);
  }
  const policyNonce = parseAmount(state.policyNonce, `${path}.policyNonce`, { max: MAX_POLICY_NONCE });
  return { protectedValue, feeReserve, paused, agentRoot, approverSlots: state.approverSlots.slice(), activeCount, approvalM, policyNonce };
}

/* v0.4 agent policy leaf — exact agent-merkle-v4 field set. */
function validateAgentPolicyShape(policy, path) {
  requireExactKeys(policy, AGENT_POLICY_FIELDS, path);
  return {
    agentPk: requireHex(policy.agentPk, 32, `${path}.agentPk`),
    maxPerSpend: parsePositiveAmount(policy.maxPerSpend, `${path}.maxPerSpend`),
    periodBudget: parsePositiveAmount(policy.periodBudget, `${path}.periodBudget`),
    periodLengthDaa: parsePositiveAmount(policy.periodLengthDaa, `${path}.periodLengthDaa`),
    periodStartDaa: parseAmount(policy.periodStartDaa, `${path}.periodStartDaa`),
    periodSpent: parseAmount(policy.periodSpent, `${path}.periodSpent`),
    approvalThreshold: parseAmount(policy.approvalThreshold, `${path}.approvalThreshold`),
    agentMaxFeePerTx: parseAmount(policy.agentMaxFeePerTx, `${path}.agentMaxFeePerTx`),
    agentRecipientRoot: requireHex(policy.agentRecipientRoot, 32, `${path}.agentRecipientRoot`)
  };
}

function validateOutpoint(op, path) {
  requireExactKeys(op, ["transactionId", "index"], path);
  return {
    transactionId: requireHex(op.transactionId, 32, `${path}.transactionId`),
    index: requireInt(op.index, `${path}.index`, { max: 0xffffffff })
  };
}

/* ------------------------------------------------------------------ */
/* requested intent v1                                                 */
/* ------------------------------------------------------------------ */

/* Per-action closed parameter schemas. Every quantity a canonical digit
 * string; every key a 32-byte lowercase hex x-only pubkey / root. */
function validateRequestedIntent(intent) {
  requireObject(intent, "requestedIntent");
  if (intent.intentVersion !== REQUESTED_INTENT_VERSION_1) {
    refuse("UNKNOWN_INTENT_VERSION", `unknown requested-intent version ${JSON.stringify(intent.intentVersion)} — failing closed`);
  }
  requireExactKeys(intent, ["intentVersion", "networkId", "vaultId", "covenantVersion", "action", "params", "maxFeeSompi"], "requestedIntent");
  requireNetworkId(intent.networkId, "requestedIntent.networkId");
  requireHex(intent.vaultId, 32, "requestedIntent.vaultId");
  if (!SUPPORTED_COVENANT_VERSIONS.includes(intent.covenantVersion)) {
    refuse("UNSUPPORTED_COVENANT_VERSION", `covenant version ${JSON.stringify(intent.covenantVersion)} is not supported by manifest v1 — failing closed`);
  }
  const requestedAction = intent.action;
  const highLevelAction = Object.prototype.hasOwnProperty.call(HIGH_LEVEL_TO_SDK, requestedAction) ? requestedAction : null;
  const sdkAction = highLevelAction ? HIGH_LEVEL_TO_SDK[requestedAction] : requestedAction;
  if (!Object.prototype.hasOwnProperty.call(ACTIONS, sdkAction)) {
    refuse("UNKNOWN_ACTION", `unknown action ${JSON.stringify(requestedAction)} — failing closed`);
  }
  if (intent.maxFeeSompi !== null) parsePositiveAmount(intent.maxFeeSompi, "requestedIntent.maxFeeSompi");

  const p = intent.params;
  const path = "requestedIntent.params";
  switch (sdkAction) {
    case "agentSpend": {
      requireExactKeys(p, ["agentPk", "recipient", "payAmountSompi", "periodsElapsed", "reserveConsumedSompi"], path);
      requireHex(p.agentPk, 32, `${path}.agentPk`);
      requireHex(p.recipient, 32, `${path}.recipient`);
      parsePositiveAmount(p.payAmountSompi, `${path}.payAmountSompi`);
      parseAmount(p.periodsElapsed, `${path}.periodsElapsed`, { max: MAX_PERIODS_ELAPSED });
      parseAmount(p.reserveConsumedSompi, `${path}.reserveConsumedSompi`);
      break;
    }
    case "ownerSetAgentRoot": {
      /* High-level lifecycle intents (addAgent / removeAgent / rotateAgent
       * / rePolicyAgent) must still pin the RESOLVED newAgentRoot — the
       * requested-vs-built binding is on the exact root commitment. */
      requireExactKeys(p, ["newAgentRoot"], path);
      requireHex(p.newAgentRoot, 32, `${path}.newAgentRoot`);
      break;
    }
    case "ownerSetApprovers": {
      requireExactKeys(p, ["newApproverSlots", "newApprovalM"], path);
      if (!Array.isArray(p.newApproverSlots) || p.newApproverSlots.length !== MAX_APPROVERS) {
        refuse("SCHEMA_INVALID", `${path}.newApproverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
      }
      p.newApproverSlots.forEach((k, i) => requireHex(k, 32, `${path}.newApproverSlots[${i}]`));
      parseAmount(p.newApprovalM, `${path}.newApprovalM`, { max: BigInt(MAX_APPROVERS) });
      break;
    }
    case "ownerTopUp": {
      requireExactKeys(p, ["topUpAmountSompi"], path);
      parsePositiveAmount(p.topUpAmountSompi, `${path}.topUpAmountSompi`);
      break;
    }
    case "ownerTopUpReserve": {
      requireExactKeys(p, ["topUpReserveAmountSompi"], path);
      parsePositiveAmount(p.topUpReserveAmountSompi, `${path}.topUpReserveAmountSompi`);
      break;
    }
    case "ownerPause":
    case "ownerUnpause":
    case "ownerRecover": {
      requireExactKeys(p, [], path);
      break;
    }
    case "createVault": {
      requireExactKeys(p, ["owner", "initialState", "agentFuel"], path);
      requireHex(p.owner, 32, `${path}.owner`);
      const st = validateStateShape(p.initialState, `${path}.initialState`);
      if (st.policyNonce !== 0n) refuse("SCHEMA_INVALID", `${path}.initialState.policyNonce must be "0" at genesis`);
      if (st.paused !== 0n) refuse("SCHEMA_INVALID", `${path}.initialState must start unpaused`);
      if (p.agentFuel !== null) {
        requireExactKeys(p.agentFuel, ["xOnly", "amountSompi"], `${path}.agentFuel`);
        requireHex(p.agentFuel.xOnly, 32, `${path}.agentFuel.xOnly`);
        parsePositiveAmount(p.agentFuel.amountSompi, `${path}.agentFuel.amountSompi`);
      }
      break;
    }
    default:
      refuse("UNKNOWN_ACTION", `unknown action ${JSON.stringify(sdkAction)} — failing closed`);
  }
  return { requestedAction, highLevelAction, sdkAction, info: ACTIONS[sdkAction] };
}

/* ------------------------------------------------------------------ */
/* decoded transaction                                                 */
/* ------------------------------------------------------------------ */

/*
 * Decoded (frozen, unsigned) transaction document: exactly the
 * canonicalFrozenTxJson field set from sdk/src/frozen-tx-v3.js, plus txId.
 * The frozen form is the security object: for version-1 Kaspa transactions
 * the txId excludes signature scripts, so this txId equals the final
 * broadcast txId.
 */
function validateTransactionShape(tx, path) {
  requireExactKeys(tx, ["txId", "version", "inputs", "outputs", "lockTime", "subnetworkId", "gas", "payload"], path);
  requireHex(tx.txId, 32, `${path}.txId`);
  if (tx.version !== 1) refuse("SCHEMA_INVALID", `${path}.version must be 1 (Toccata)`);
  parseAmount(tx.lockTime, `${path}.lockTime`, { max: (1n << 64n) - 1n });
  if (tx.subnetworkId !== NATIVE_SUBNETWORK) refuse("SCHEMA_INVALID", `${path}.subnetworkId must be the native subnetwork`);
  if (tx.gas !== "0") refuse("SCHEMA_INVALID", `${path}.gas must be "0"`);
  if (tx.payload !== "") refuse("SCHEMA_INVALID", `${path}.payload must be empty`);
  if (!Array.isArray(tx.inputs) || tx.inputs.length === 0) refuse("SCHEMA_INVALID", `${path}.inputs must be a non-empty array`);
  if (!Array.isArray(tx.outputs) || tx.outputs.length === 0) refuse("SCHEMA_INVALID", `${path}.outputs must be a non-empty array`);

  const inputs = tx.inputs.map((input, i) => {
    const ip = `${path}.inputs[${i}]`;
    requireExactKeys(input, ["previousOutpoint", "sequence", "computeBudget", "utxo"], ip);
    const previousOutpoint = validateOutpoint(input.previousOutpoint, `${ip}.previousOutpoint`);
    const sequence = parseAmount(input.sequence, `${ip}.sequence`, { max: (1n << 64n) - 1n });
    const computeBudget = requireInt(input.computeBudget, `${ip}.computeBudget`, { max: 0xffff });
    requireExactKeys(input.utxo, ["amount", "scriptPublicKey", "covenantId", "blockDaaScore"], `${ip}.utxo`);
    requireExactKeys(input.utxo.scriptPublicKey, ["version", "scriptHex"], `${ip}.utxo.scriptPublicKey`);
    const utxo = {
      amount: parsePositiveAmount(input.utxo.amount, `${ip}.utxo.amount`),
      scriptVersion: requireInt(input.utxo.scriptPublicKey.version, `${ip}.utxo.scriptPublicKey.version`, { max: 0xffff }),
      scriptHex: requireEvenHex(input.utxo.scriptPublicKey.scriptHex, `${ip}.utxo.scriptPublicKey.scriptHex`),
      covenantId: input.utxo.covenantId === null ? null : requireHex(input.utxo.covenantId, 32, `${ip}.utxo.covenantId`),
      blockDaaScore: parseAmount(input.utxo.blockDaaScore, `${ip}.utxo.blockDaaScore`)
    };
    return { previousOutpoint, sequence, computeBudget, utxo };
  });

  const outputs = tx.outputs.map((output, i) => {
    const op = `${path}.outputs[${i}]`;
    requireExactKeys(output, ["value", "scriptPublicKey", "covenant"], op);
    requireExactKeys(output.scriptPublicKey, ["version", "scriptHex"], `${op}.scriptPublicKey`);
    let covenant = null;
    if (output.covenant !== null) {
      requireExactKeys(output.covenant, ["authorizingInput", "covenantId"], `${op}.covenant`);
      covenant = {
        authorizingInput: requireInt(output.covenant.authorizingInput, `${op}.covenant.authorizingInput`, { max: 0xffff }),
        covenantId: requireHex(output.covenant.covenantId, 32, `${op}.covenant.covenantId`)
      };
    }
    return {
      value: parsePositiveAmount(output.value, `${op}.value`),
      scriptVersion: requireInt(output.scriptPublicKey.version, `${op}.scriptPublicKey.version`, { max: 0xffff }),
      scriptHex: requireEvenHex(output.scriptPublicKey.scriptHex, `${op}.scriptPublicKey.scriptHex`),
      covenant
    };
  });

  return { txId: tx.txId, lockTime: parseAmount(tx.lockTime, `${path}.lockTime`), inputs, outputs };
}

/* effects: one classification entry per transaction input/output, in
 * order. Covenant-bearing consistency is structural: an input is
 * "covenant" iff its UTXO carries a covenantId; an output is
 * "successor"/"genesisVault" iff it carries a covenant binding. */
function validateEffects(effects, txView, path) {
  requireExactKeys(effects, ["inputs", "outputs"], path);
  if (!Array.isArray(effects.inputs) || effects.inputs.length !== txView.inputs.length) {
    refuse("SCHEMA_INVALID", `${path}.inputs must classify every transaction input exactly once`);
  }
  if (!Array.isArray(effects.outputs) || effects.outputs.length !== txView.outputs.length) {
    refuse("SCHEMA_INVALID", `${path}.outputs must classify every transaction output exactly once`);
  }
  effects.inputs.forEach((entry, i) => {
    requireExactKeys(entry, ["index", "kind"], `${path}.inputs[${i}]`);
    if (entry.index !== i) refuse("SCHEMA_INVALID", `${path}.inputs[${i}].index must be ${i} (in order)`);
    if (!INPUT_KINDS.includes(entry.kind)) refuse("SCHEMA_INVALID", `${path}.inputs[${i}].kind must be one of ${INPUT_KINDS.join("/")}`);
    const hasCovenantId = txView.inputs[i].utxo.covenantId !== null;
    if ((entry.kind === "covenant") !== hasCovenantId) {
      refuse("SCHEMA_INVALID", `${path}.inputs[${i}] kind ${entry.kind} contradicts the input's covenantId presence`);
    }
  });
  effects.outputs.forEach((entry, i) => {
    requireExactKeys(entry, ["index", "kind"], `${path}.outputs[${i}]`);
    if (entry.index !== i) refuse("SCHEMA_INVALID", `${path}.outputs[${i}].index must be ${i} (in order)`);
    if (!OUTPUT_KINDS.includes(entry.kind)) refuse("SCHEMA_INVALID", `${path}.outputs[${i}].kind must be one of ${OUTPUT_KINDS.join("/")}`);
    const bound = txView.outputs[i].covenant !== null;
    const boundKind = entry.kind === "successor" || entry.kind === "genesisVault";
    if (boundKind !== bound) {
      refuse("SCHEMA_INVALID", `${path}.outputs[${i}] kind ${entry.kind} contradicts the output's covenant binding`);
    }
  });
  return {
    inputKinds: effects.inputs.map((e) => e.kind),
    outputKinds: effects.outputs.map((e) => e.kind)
  };
}

function validateNotes(list, path) {
  if (!Array.isArray(list)) refuse("SCHEMA_INVALID", `${path} must be an array`);
  list.forEach((entry, i) => {
    requireExactKeys(entry, ["code", "detail"], `${path}[${i}]`);
    requireCode(entry.code, `${path}[${i}].code`);
    requireDetail(entry.detail, `${path}[${i}].detail`);
  });
}

/* ------------------------------------------------------------------ */
/* full manifest validation                                            */
/* ------------------------------------------------------------------ */

const MANIFEST_KEYS = Object.freeze([
  "manifestVersion",
  "network",
  "vault",
  "action",
  "actor",
  "requested",
  "transaction",
  "effects",
  "stateBefore",
  "stateAfter",
  "accounting",
  "payment",
  "allowlist",
  "approvals",
  "limits",
  "policyMutations",
  "warnings",
  "unexpectedEffects",
  "manifestHash"
]);

/*
 * STRICT fail-closed validation of a complete manifest document.
 * Shape, domains, closed key sets, identity cross-references, and the
 * representation-independent hash. Value EQUATIONS (state transitions,
 * conservation, request binding, detectors) live in verify.js.
 *
 * Returns a parsed context view for the verifier. Throws coded errors:
 * UNKNOWN_MANIFEST_VERSION / UNSUPPORTED_COVENANT_VERSION /
 * UNKNOWN_ACTION / UNKNOWN_INTENT_VERSION / SCHEMA_INVALID /
 * VALUE_INVALID / MANIFEST_HASH_MISMATCH.
 */
function validateManifest(manifest) {
  requireObject(manifest, "manifest");
  /* Version FIRST: an unknown version must refuse with its own code before
   * any structural assumption is applied — never route to a default. */
  if (manifest.manifestVersion !== MANIFEST_VERSION_1) {
    refuse("UNKNOWN_MANIFEST_VERSION", `unknown manifest version ${JSON.stringify(manifest.manifestVersion)} — failing closed`);
  }
  requireExactKeys(manifest, MANIFEST_KEYS, "manifest");

  /* network / vault */
  requireExactKeys(manifest.network, ["networkId"], "manifest.network");
  requireNetworkId(manifest.network.networkId, "manifest.network.networkId");
  requireExactKeys(manifest.vault, ["vaultId", "owner", "covenantVersion", "covenantId"], "manifest.vault");
  requireHex(manifest.vault.vaultId, 32, "manifest.vault.vaultId");
  requireHex(manifest.vault.owner, 32, "manifest.vault.owner");
  if (!SUPPORTED_COVENANT_VERSIONS.includes(manifest.vault.covenantVersion)) {
    refuse("UNSUPPORTED_COVENANT_VERSION", `covenant version ${JSON.stringify(manifest.vault.covenantVersion)} is not supported by manifest v1 — failing closed`);
  }
  requireHex(manifest.vault.covenantId, 32, "manifest.vault.covenantId");

  /* action — unknown actions refuse with their own code before the walk. */
  requireObject(manifest.action, "manifest.action");
  const sdkAction = manifest.action.sdkAction;
  if (typeof sdkAction !== "string" || !Object.prototype.hasOwnProperty.call(ACTIONS, sdkAction)) {
    refuse("UNKNOWN_ACTION", `unknown action ${JSON.stringify(sdkAction)} — failing closed`);
  }
  const info = ACTIONS[sdkAction];
  requireExactKeys(manifest.action, ["sdkAction", "highLevelAction", "role", "genesis", "terminal", "aboveThreshold"], "manifest.action");
  const highLevel = manifest.action.highLevelAction;
  if (highLevel !== null) {
    if (!Object.prototype.hasOwnProperty.call(HIGH_LEVEL_TO_SDK, highLevel) || HIGH_LEVEL_TO_SDK[highLevel] !== sdkAction) {
      refuse("SCHEMA_INVALID", `manifest.action.highLevelAction ${JSON.stringify(highLevel)} does not map to ${sdkAction}`);
    }
  }
  if (manifest.action.role !== info.role) refuse("SCHEMA_INVALID", `manifest.action.role must be ${JSON.stringify(info.role)} for ${sdkAction}`);
  if (requireBool(manifest.action.genesis, "manifest.action.genesis") !== info.genesis) {
    refuse("SCHEMA_INVALID", `manifest.action.genesis must be ${info.genesis} for ${sdkAction}`);
  }
  if (requireBool(manifest.action.terminal, "manifest.action.terminal") !== info.terminal) {
    refuse("SCHEMA_INVALID", `manifest.action.terminal must be ${info.terminal} for ${sdkAction}`);
  }
  requireBool(manifest.action.aboveThreshold, "manifest.action.aboveThreshold");
  if (manifest.action.aboveThreshold && sdkAction !== "agentSpend") {
    refuse("SCHEMA_INVALID", "manifest.action.aboveThreshold can be true only for agentSpend");
  }

  /* actor — canonical identity is the x-only pubkey (never an address). */
  requireExactKeys(manifest.actor, ["role", "signerXOnly", "agentPk"], "manifest.actor");
  if (manifest.actor.role !== info.role) refuse("SCHEMA_INVALID", `manifest.actor.role must be ${JSON.stringify(info.role)} for ${sdkAction}`);
  requireHex(manifest.actor.signerXOnly, 32, "manifest.actor.signerXOnly");
  if (sdkAction === "agentSpend") {
    requireHex(manifest.actor.agentPk, 32, "manifest.actor.agentPk");
    if (manifest.actor.agentPk !== manifest.actor.signerXOnly) {
      refuse("SCHEMA_INVALID", "manifest.actor.agentPk must equal manifest.actor.signerXOnly for agentSpend (the acting agent signs)");
    }
  } else {
    if (manifest.actor.agentPk !== null) refuse("SCHEMA_INVALID", "manifest.actor.agentPk must be null for owner actions");
    if (manifest.actor.signerXOnly !== manifest.vault.owner) {
      refuse("SCHEMA_INVALID", `${sdkAction} is an owner operation — manifest.actor.signerXOnly must equal manifest.vault.owner`);
    }
  }

  /* requested intent — embedded, and identity-bound to this manifest. */
  const requested = validateRequestedIntent(manifest.requested);
  if (requested.sdkAction !== sdkAction) {
    refuse("SCHEMA_INVALID", `manifest.requested action resolves to ${requested.sdkAction}, but manifest.action.sdkAction is ${sdkAction}`);
  }
  if (requested.highLevelAction !== highLevel) {
    refuse("SCHEMA_INVALID", "manifest.action.highLevelAction must equal the requested high-level action (or null)");
  }
  if (manifest.requested.networkId !== manifest.network.networkId) {
    refuse("SCHEMA_INVALID", "manifest.requested.networkId differs from manifest.network.networkId");
  }
  if (manifest.requested.vaultId !== manifest.vault.vaultId) {
    refuse("SCHEMA_INVALID", "manifest.requested.vaultId differs from manifest.vault.vaultId");
  }
  if (manifest.requested.covenantVersion !== manifest.vault.covenantVersion) {
    refuse("SCHEMA_INVALID", "manifest.requested.covenantVersion differs from manifest.vault.covenantVersion");
  }

  /* transaction + effects */
  const txView = validateTransactionShape(manifest.transaction, "manifest.transaction");
  const effects = validateEffects(manifest.effects, txView, "manifest.effects");

  /* stateBefore / stateAfter null-ness matrix */
  let stateBefore = null;
  if (info.genesis) {
    if (manifest.stateBefore !== null) refuse("SCHEMA_INVALID", "manifest.stateBefore must be null for genesis (createVault)");
  } else {
    requireExactKeys(manifest.stateBefore, ["outpoint", "stateId", "state"], "manifest.stateBefore");
    stateBefore = {
      outpoint: validateOutpoint(manifest.stateBefore.outpoint, "manifest.stateBefore.outpoint"),
      stateId: requireHex(manifest.stateBefore.stateId, 32, "manifest.stateBefore.stateId"),
      state: validateStateShape(manifest.stateBefore.state, "manifest.stateBefore.state")
    };
  }
  let stateAfter = null;
  if (info.terminal) {
    if (manifest.stateAfter !== null) refuse("SCHEMA_INVALID", "manifest.stateAfter must be null for the terminal action (ownerRecover)");
  } else {
    requireExactKeys(manifest.stateAfter, ["stateId", "state", "expectedOutpoint"], "manifest.stateAfter");
    stateAfter = {
      stateId: requireHex(manifest.stateAfter.stateId, 32, "manifest.stateAfter.stateId"),
      state: validateStateShape(manifest.stateAfter.state, "manifest.stateAfter.state"),
      expectedOutpoint: validateOutpoint(manifest.stateAfter.expectedOutpoint, "manifest.stateAfter.expectedOutpoint")
    };
  }

  /* accounting — the exact 11 builder fields, all canonical amounts. */
  requireExactKeys(manifest.accounting, ACCOUNTING_FIELDS, "manifest.accounting");
  const accounting = {};
  for (const field of ACCOUNTING_FIELDS) {
    accounting[field] = parseAmount(manifest.accounting[field], `manifest.accounting.${field}`);
  }

  /* agentSpend-only sections (null-ness matrix). */
  const isSpend = sdkAction === "agentSpend";
  let payment = null;
  let allowlist = null;
  let approvals = null;
  let limits = null;
  if (isSpend) {
    requireExactKeys(manifest.payment, ["recipientXOnly", "amountSompi", "outputIndex"], "manifest.payment");
    payment = {
      recipientXOnly: requireHex(manifest.payment.recipientXOnly, 32, "manifest.payment.recipientXOnly"),
      amountSompi: parsePositiveAmount(manifest.payment.amountSompi, "manifest.payment.amountSompi"),
      outputIndex: requireInt(manifest.payment.outputIndex, "manifest.payment.outputIndex", { max: txView.outputs.length - 1 })
    };
    requireExactKeys(manifest.allowlist, ["agentRecipientRoot", "recipientAllowlisted", "proofSupplied"], "manifest.allowlist");
    allowlist = {
      agentRecipientRoot: requireHex(manifest.allowlist.agentRecipientRoot, 32, "manifest.allowlist.agentRecipientRoot"),
      recipientAllowlisted: requireBool(manifest.allowlist.recipientAllowlisted, "manifest.allowlist.recipientAllowlisted"),
      proofSupplied: requireBool(manifest.allowlist.proofSupplied, "manifest.allowlist.proofSupplied")
    };
    requireExactKeys(manifest.approvals, ["aboveThreshold", "approvalThreshold", "requiredM"], "manifest.approvals");
    approvals = {
      aboveThreshold: requireBool(manifest.approvals.aboveThreshold, "manifest.approvals.aboveThreshold"),
      approvalThreshold: parseAmount(manifest.approvals.approvalThreshold, "manifest.approvals.approvalThreshold"),
      requiredM: parseAmount(manifest.approvals.requiredM, "manifest.approvals.requiredM", { max: BigInt(MAX_APPROVERS) })
    };
    if (approvals.aboveThreshold !== manifest.action.aboveThreshold) {
      refuse("SCHEMA_INVALID", "manifest.approvals.aboveThreshold must equal manifest.action.aboveThreshold");
    }
    requireExactKeys(manifest.limits, ["policyBefore", "policyAfter", "periodsElapsed"], "manifest.limits");
    limits = {
      policyBefore: validateAgentPolicyShape(manifest.limits.policyBefore, "manifest.limits.policyBefore"),
      policyAfter: validateAgentPolicyShape(manifest.limits.policyAfter, "manifest.limits.policyAfter"),
      periodsElapsed: parseAmount(manifest.limits.periodsElapsed, "manifest.limits.periodsElapsed", { max: MAX_PERIODS_ELAPSED })
    };
  } else {
    if (manifest.payment !== null) refuse("SCHEMA_INVALID", `manifest.payment must be null for ${sdkAction}`);
    if (manifest.allowlist !== null) refuse("SCHEMA_INVALID", `manifest.allowlist must be null for ${sdkAction}`);
    if (manifest.approvals !== null) refuse("SCHEMA_INVALID", `manifest.approvals must be null for ${sdkAction}`);
    if (manifest.limits !== null) refuse("SCHEMA_INVALID", `manifest.limits must be null for ${sdkAction}`);
  }

  /* policyMutations — the explicit state-diff declaration. */
  if (!Array.isArray(manifest.policyMutations)) refuse("SCHEMA_INVALID", "manifest.policyMutations must be an array");
  if ((info.genesis || info.terminal) && manifest.policyMutations.length !== 0) {
    refuse("SCHEMA_INVALID", "manifest.policyMutations must be empty for genesis/terminal actions (no predecessor/successor pair to diff)");
  }
  const seenFields = new Set();
  manifest.policyMutations.forEach((entry, i) => {
    requireExactKeys(entry, ["field", "before", "after"], `manifest.policyMutations[${i}]`);
    if (!STATE_FIELDS.includes(entry.field)) {
      refuse("SCHEMA_INVALID", `manifest.policyMutations[${i}].field ${JSON.stringify(entry.field)} is not a state field`);
    }
    if (seenFields.has(entry.field)) refuse("SCHEMA_INVALID", `manifest.policyMutations declares ${entry.field} twice`);
    seenFields.add(entry.field);
    const checkSide = (side, label) => {
      if (entry.field === "approverSlots") {
        if (!Array.isArray(side) || side.length !== MAX_APPROVERS) {
          refuse("SCHEMA_INVALID", `manifest.policyMutations[${i}].${label} must be a ${MAX_APPROVERS}-slot array for approverSlots`);
        }
        side.forEach((k, j) => requireHex(k, 32, `manifest.policyMutations[${i}].${label}[${j}]`));
      } else if (entry.field === "agentRoot") {
        requireHex(side, 32, `manifest.policyMutations[${i}].${label}`);
      } else {
        parseAmount(side, `manifest.policyMutations[${i}].${label}`);
      }
    };
    checkSide(entry.before, "before");
    checkSide(entry.after, "after");
  });

  /* warnings + unexpectedEffects. The unexpectedEffects FIELD exists so an
   * upstream builder that detects something unexplained can RECORD it —
   * verify.js refuses any manifest where it is non-empty. */
  validateNotes(manifest.warnings, "manifest.warnings");
  validateNotes(manifest.unexpectedEffects, "manifest.unexpectedEffects");

  /* manifest hash LAST (over the structurally valid body). */
  requireHex(manifest.manifestHash, 32, "manifest.manifestHash");
  const body = {};
  for (const k of MANIFEST_KEYS) {
    if (k !== "manifestHash") body[k] = manifest[k];
  }
  const recomputed = computeManifestHashV1(body);
  if (recomputed !== manifest.manifestHash) {
    refuse(
      "MANIFEST_HASH_MISMATCH",
      "manifest hash does not match a recomputation over the canonical serialization — the manifest was mutated after it was built (or was built with a non-canonical hasher)"
    );
  }

  return {
    manifest,
    sdkAction,
    info,
    txView,
    effects,
    stateBefore,
    stateAfter,
    accounting,
    payment,
    allowlist,
    approvals,
    limits
  };
}

/* ------------------------------------------------------------------ */
/* deterministic state diff                                            */
/* ------------------------------------------------------------------ */

/*
 * The canonical policy-mutation diff between two state documents (JSON
 * form), in fixed STATE_FIELDS order. Deterministic: same states -> same
 * diff array, always.
 */
function diffStates(beforeState, afterState) {
  const diff = [];
  for (const field of STATE_FIELDS) {
    const b = beforeState[field];
    const a = afterState[field];
    const equal = field === "approverSlots" ? canonicalJsonStringify(b) === canonicalJsonStringify(a) : b === a;
    if (!equal) {
      diff.push({
        field,
        before: field === "approverSlots" ? b.slice() : b,
        after: field === "approverSlots" ? a.slice() : a
      });
    }
  }
  return diff;
}

/* ------------------------------------------------------------------ */
/* build                                                               */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

/*
 * Assemble a v1 manifest from structured inputs (in a real integration:
 * the requested intent, the SDK build output bridged to JSON — frozen tx
 * via canonicalFrozenTxJson + txId, states via stateToJsonV4, the builder
 * accounting object — and the effect classification). The builder DERIVES
 * action metadata, the policy-mutation diff, the expected successor
 * outpoint, and the manifest hash; it accepts NO caller-supplied verdict.
 * The result is re-validated through the full strict schema before it is
 * returned — buildIntentManifest can never emit an invalid manifest — and
 * the caller is expected to run verifyIntentManifest before trusting it.
 */
function buildIntentManifest(inputs) {
  requireObject(inputs, "inputs");
  requireExactKeys(
    inputs,
    [
      "requestedIntent",
      "network",
      "vault",
      "signerXOnly",
      "transaction",
      "effects",
      "stateBefore",
      "stateAfter",
      "accounting",
      "payment",
      "allowlist",
      "approvals",
      "limits",
      "warnings",
      "unexpectedEffects"
    ],
    "inputs"
  );

  const requested = validateRequestedIntent(inputs.requestedIntent);
  const info = requested.info;

  /* effects: accept plain kind-string arrays; expand to {index, kind}. */
  requireExactKeys(inputs.effects, ["inputs", "outputs"], "inputs.effects");
  if (!Array.isArray(inputs.effects.inputs) || !Array.isArray(inputs.effects.outputs)) {
    refuse("SCHEMA_INVALID", "inputs.effects.inputs/outputs must be arrays of kind strings");
  }
  const effects = {
    inputs: inputs.effects.inputs.map((kind, index) => ({ index, kind })),
    outputs: inputs.effects.outputs.map((kind, index) => ({ index, kind }))
  };

  /* Derived action metadata — the builder computes it; callers cannot
   * claim a role/genesis/terminal combination the action table refutes. */
  const aboveThreshold = requested.sdkAction === "agentSpend" ? requireBool(requireObject(inputs.approvals, "inputs.approvals").aboveThreshold, "inputs.approvals.aboveThreshold") : false;
  const action = {
    sdkAction: requested.sdkAction,
    highLevelAction: requested.highLevelAction,
    role: info.role,
    genesis: info.genesis,
    terminal: info.terminal,
    aboveThreshold
  };
  const actor = {
    role: info.role,
    signerXOnly: requireHex(inputs.signerXOnly, 32, "inputs.signerXOnly"),
    agentPk: requested.sdkAction === "agentSpend" ? requireHex(inputs.signerXOnly, 32, "inputs.signerXOnly") : null
  };

  /* stateAfter.expectedOutpoint: DERIVED — txId of this transaction plus
   * the index of its covenant-bound (successor / genesisVault) output. */
  let stateAfter = null;
  if (!info.terminal) {
    requireObject(inputs.stateAfter, "inputs.stateAfter");
    requireExactKeys(inputs.stateAfter, ["stateId", "state"], "inputs.stateAfter");
    const txDoc = requireObject(inputs.transaction, "inputs.transaction");
    const boundIndex = effects.outputs.findIndex((e) => e.kind === "successor" || e.kind === "genesisVault");
    if (boundIndex < 0) refuse("SCHEMA_INVALID", "a non-terminal manifest requires a successor/genesisVault output classification");
    stateAfter = {
      stateId: inputs.stateAfter.stateId,
      state: inputs.stateAfter.state,
      expectedOutpoint: { transactionId: txDoc.txId, index: boundIndex }
    };
  } else if (inputs.stateAfter !== null) {
    refuse("SCHEMA_INVALID", "inputs.stateAfter must be null for the terminal action");
  }

  /* policyMutations: DERIVED deterministic diff — never caller-supplied. */
  let policyMutations = [];
  if (!info.genesis && !info.terminal) {
    const beforeDoc = requireObject(inputs.stateBefore, "inputs.stateBefore");
    requireExactKeys(beforeDoc, ["outpoint", "stateId", "state"], "inputs.stateBefore");
    validateStateShape(beforeDoc.state, "inputs.stateBefore.state");
    validateStateShape(stateAfter.state, "inputs.stateAfter.state");
    policyMutations = diffStates(beforeDoc.state, stateAfter.state);
  }

  const body = {
    manifestVersion: MANIFEST_VERSION_1,
    network: inputs.network,
    vault: inputs.vault,
    action,
    actor,
    requested: inputs.requestedIntent,
    transaction: inputs.transaction,
    effects,
    stateBefore: info.genesis ? null : inputs.stateBefore,
    stateAfter,
    accounting: inputs.accounting,
    payment: inputs.payment,
    allowlist: inputs.allowlist,
    approvals: inputs.approvals,
    limits: inputs.limits,
    policyMutations,
    warnings: inputs.warnings ?? [],
    unexpectedEffects: inputs.unexpectedEffects ?? []
  };
  const manifest = { ...body, manifestHash: computeManifestHashV1(body) };

  /* Self-check: the builder can never return an invalid manifest. */
  validateManifest(manifest);
  return deepFreeze(manifest);
}

module.exports = {
  MANIFEST_VERSION_1,
  REQUESTED_INTENT_VERSION_1,
  SUPPORTED_COVENANT_VERSIONS,
  SOMPI_PER_KAS,
  MAX_SOMPI,
  MAX_APPROVERS,
  APPROVER_SENTINEL,
  NATIVE_SUBNETWORK,
  MAX_POLICY_NONCE,
  MAX_PERIODS_ELAPSED,
  ACTIONS,
  HIGH_LEVEL_TO_SDK,
  STATE_FIELDS,
  AGENT_POLICY_FIELDS,
  ACCOUNTING_FIELDS,
  INPUT_KINDS,
  OUTPUT_KINDS,
  refuse,
  parseAmount,
  parsePositiveAmount,
  requireInt,
  requireHex,
  requireEvenHex,
  p2pkScriptHex,
  validateStateShape,
  validateAgentPolicyShape,
  validateRequestedIntent,
  validateTransactionShape,
  validateManifest,
  diffStates,
  buildIntentManifest
};
