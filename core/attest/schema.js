"use strict";

/*
 * policyvault-execution-attestation/1 — SCHEMA + FAIL-CLOSED STRUCTURAL
 * CHECK. Spec: docs/postlaunch/execution-attestation-spec.md.
 *
 * What an attestation IS: a machine-verifiable, self-describing EVIDENCE
 * RECORD about one PolicyVault policy-execution attempt — what was
 * requested, what PolicyVault deterministically decided, what the signer
 * saw, and exactly what was observed on Kaspa. Its authority comes from
 * chain-verifiable facts a third party can re-check against a node, never
 * from PolicyVault's say-so and never from a signature slot.
 *
 * What it is NOT: a certificate, a rating, a licence, a regulatory
 * artifact, or an endorsement of any counterparty. See summary.js for the
 * language rules this project binds itself to.
 *
 * DESIGN RULES ENFORCED HERE
 *  - EXACT-MATCH VERSION: attestationVersion must equal the one supported
 *    version string. Unknown version => fail closed, never routed to a
 *    default (CLAUDE.md versioning rule).
 *  - CLOSED KEY SETS everywhere: an unexpected key is a failure, not
 *    ignored data. A record cannot smuggle fields past a verifier.
 *  - NUMERIC SAFETY: every consensus/accounting value is a canonical
 *    decimal STRING of a non-negative integer (BigInt at rest in JS,
 *    u64 on the wire). No floats, no exponents, no leading zeroes, no
 *    negatives, no unsafe-integer JSON numbers.
 *  - NOT_AVAILABLE IS EXPLICIT: a field the durable records genuinely do
 *    not carry is the literal string "NOT_AVAILABLE". It is permitted
 *    ONLY in the fields listed as optional here, and NEVER in a field the
 *    reached ladder state depends on. Nothing is ever fabricated.
 *  - THE LADDER IS NEVER COLLAPSED: AUTHORIZED -> SIGNED -> BROADCAST ->
 *    CHAIN_SEEN -> CHAIN_VERIFIED -> VERIFIED_OUTCOME, and `reached` must
 *    be a contiguous PREFIX of it (dex-adapter-design-spec.md §5/§9).
 *    "authorized", "broadcast" and "settled" are different sentences.
 *  - NO SECRETS: the schema has no slot for a private key, seed, bearer
 *    token, session/token hash, prompt, or personal data. Approver
 *    evidence is counts + public x-only keys + per-approval sha256
 *    DIGESTS, never raw signatures (see §approvals below).
 */

const { canonicalJsonStringify } = require("./canonical");

const ATTESTATION_VERSION_1 = "policyvault-execution-attestation/1";
const BATCH_VERSION_1 = "policyvault-execution-attestation-batch/1";
const VERIFIER_VERSION_1 = "policyvault-attestation-verifier/1";
const SIGNATURE_SCHEME_1 = "policyvault-attestation-signature/1";

/* The explicit "this durable record does not carry that fact" sentinel. */
const NOT_AVAILABLE = "NOT_AVAILABLE";

/* Reconciliation ladder — order is meaningful and never collapsed. */
const LADDER = Object.freeze(["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED", "VERIFIED_OUTCOME"]);
const LADDER_INDEX = Object.freeze(Object.fromEntries(LADDER.map((s, i) => [s, i])));

const DECISIONS = Object.freeze(["AUTHORIZED", "REFUSED"]);
const DISPOSITIONS = Object.freeze(["REFUSED", "IN_PROGRESS", "SETTLED", "FAILED", "UNKNOWN"]);
const ROLES = Object.freeze(["owner", "agent", "approver", "system"]);
const ASSET_KINDS = Object.freeze(["KAS", "TOKEN"]);
const ASSET_UNITS = Object.freeze(["sompi", "atomic"]);
const DESTINATION_KINDS = Object.freeze([
  "RECIPIENT_XONLY",
  "ADDRESS",
  "COVENANT_SUCCESSOR",
  "OWNER_PAYOUT",
  "VENUE_POOL",
  "NONE"
]);
const MANIFEST_VERDICTS = Object.freeze(["VERIFIED_EXACT", "REFUSED"]);

/*
 * Closed set of covenant generations an attestation may name. UNKNOWN
 * VERSIONS FAIL CLOSED — a substituted or invented policy/covenant
 * generation is refused rather than routed to a default. Extending this
 * list is an additive, deliberate change that lands with its own tests.
 */
const SUPPORTED_CONTRACT_VERSIONS = Object.freeze([
  "policyvault-0.2",
  "policyvault-0.3",
  "policyvault-0.4",
  "policyvault-0.4.1",
  "policyvault-0.5",
  "policyvault-0.6",
  /* v0.7 ORGANIZATIONAL M-of-N OWNER ROOT (Wave 2, Track G): the root's own
   * governance actions (authorize/rotate/freeze/unfreeze/ownerRecover/
   * succession) attest under policyvault-0.7-root; rooted-vault owner
   * operations riding in the SAME root transaction, and standalone
   * delegate-spend/deposit requests on a rooted vault (no root input),
   * attest under policyvault-0.7-payment. See core/attest/org-root-v7.js. */
  "policyvault-0.7-root",
  "policyvault-0.7-payment"
]);

const SOMPI_PER_KAS = 100000000n;
const MAX_SOMPI = 29000000000n * SOMPI_PER_KAS; // total KAS supply bound
const U64_MAX = 18446744073709551615n;
const MAX_APPROVER_SLOTS = 10;
const MAX_CHAIN_OUTPUTS = 64;
const MAX_STRING = 512;

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX_RE = /^(?:[0-9a-f]{2})*$/;
const DECIMAL_RE = /^(?:0|[1-9][0-9]{0,19})$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NETWORK_RE = /^[a-z0-9-]{1,32}$/;
const IDENT_RE = /^[A-Za-z0-9_.:@/+-]{1,120}$/;

/* ------------------------------------------------------------------ */
/* failure accumulation                                                */
/* ------------------------------------------------------------------ */

class Failures {
  constructor() {
    this.failures = [];
    this.warnings = [];
  }
  add(code, path, message) {
    this.failures.push({ code, path, message });
    return false;
  }
  warn(code, path, message) {
    this.warnings.push({ code, path, message });
  }
  get ok() {
    return this.failures.length === 0;
  }
}

/* ------------------------------------------------------------------ */
/* primitive checkers (each returns true/false and records a failure)  */
/* ------------------------------------------------------------------ */

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function exactKeys(f, value, path, keys) {
  if (!isPlainObject(value)) return f.add("SCHEMA_INVALID", path, "must be a plain object");
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJsonStringify(actual) !== canonicalJsonStringify(expected)) {
    const missing = expected.filter((k) => !actual.includes(k));
    const extra = actual.filter((k) => !expected.includes(k));
    return f.add(
      "SCHEMA_INVALID",
      path,
      `key set mismatch (missing: ${missing.join(",") || "-"}; unexpected: ${extra.join(",") || "-"})`
    );
  }
  return true;
}

function str(f, value, path, { max = MAX_STRING, re = null, allowNotAvailable = false } = {}) {
  if (allowNotAvailable && value === NOT_AVAILABLE) return true;
  if (typeof value !== "string") return f.add("SCHEMA_INVALID", path, "must be a string");
  if (value.length === 0 || value.length > max) return f.add("SCHEMA_INVALID", path, `string length out of range (1..${max})`);
  if (re && !re.test(value)) return f.add("SCHEMA_INVALID", path, "string does not match the required form");
  if (!allowNotAvailable && value === NOT_AVAILABLE) {
    return f.add("NOT_AVAILABLE_NOT_PERMITTED", path, "the NOT_AVAILABLE sentinel is not permitted in this field");
  }
  return true;
}

function hex64(f, value, path, { nullable = false, allowNotAvailable = false } = {}) {
  if (nullable && value === null) return true;
  if (allowNotAvailable && value === NOT_AVAILABLE) return true;
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    return f.add("SCHEMA_INVALID", path, "must be lowercase 32-byte hex (64 chars)");
  }
  return true;
}

function decimal(f, value, path, { max = MAX_SOMPI, nullable = false, allowNotAvailable = false } = {}) {
  if (nullable && value === null) return true;
  if (allowNotAvailable && value === NOT_AVAILABLE) return true;
  if (typeof value !== "string") return f.add("NUMERIC_INVALID", path, "consensus/accounting values must be decimal STRINGS, never JSON numbers");
  if (!DECIMAL_RE.test(value)) return f.add("NUMERIC_INVALID", path, "not a canonical non-negative decimal integer string");
  let n;
  try {
    n = BigInt(value);
  } catch {
    return f.add("NUMERIC_INVALID", path, "not parseable as an integer");
  }
  if (n < 0n || n > max) return f.add("NUMERIC_INVALID", path, `value out of range (0..${max})`);
  return true;
}

function bool(f, value, path) {
  if (typeof value !== "boolean") return f.add("SCHEMA_INVALID", path, "must be a boolean");
  return true;
}

function enumOf(f, value, path, allowed, { allowNotAvailable = false } = {}) {
  if (allowNotAvailable && value === NOT_AVAILABLE) return true;
  if (typeof value !== "string" || !allowed.includes(value)) {
    return f.add("SCHEMA_INVALID", path, `must be one of ${allowed.join("|")}`);
  }
  return true;
}

function outpoint(f, value, path, { nullable = false } = {}) {
  if (nullable && value === null) return true;
  if (!exactKeys(f, value, path, ["transactionId", "index"])) return false;
  let ok = hex64(f, value.transactionId, `${path}.transactionId`);
  if (!Number.isInteger(value.index) || value.index < 0 || value.index > 0xffff) {
    ok = f.add("SCHEMA_INVALID", `${path}.index`, "must be an integer 0..65535");
  }
  return ok;
}

/* ------------------------------------------------------------------ */
/* section checkers                                                    */
/* ------------------------------------------------------------------ */

function checkProducer(f, v) {
  if (!exactKeys(f, v, "producer", ["software", "buildId", "component", "sources"])) return;
  str(f, v.software, "producer.software", { re: IDENT_RE });
  str(f, v.buildId, "producer.buildId", { re: IDENT_RE, allowNotAvailable: true });
  str(f, v.component, "producer.component", { re: IDENT_RE });
  if (!Array.isArray(v.sources) || v.sources.length === 0 || v.sources.length > 16) {
    f.add("SCHEMA_INVALID", "producer.sources", "must be a non-empty array (<=16) of durable-record schema names");
    return;
  }
  v.sources.forEach((s, i) => str(f, s, `producer.sources[${i}]`, { re: IDENT_RE }));
}

function checkSubject(f, v) {
  if (!exactKeys(f, v, "subject", ["requestId", "vaultId", "organizationId", "networkId", "contractVersion", "policyNonce", "stateBefore", "stateAfter"])) return;
  if (v.requestId !== NOT_AVAILABLE) str(f, v.requestId, "subject.requestId", { re: UUID_RE });
  hex64(f, v.vaultId, "subject.vaultId");
  if (v.organizationId !== null) str(f, v.organizationId, "subject.organizationId", { re: UUID_RE });
  str(f, v.networkId, "subject.networkId", { re: NETWORK_RE });
  if (str(f, v.contractVersion, "subject.contractVersion", { re: IDENT_RE }) && !SUPPORTED_CONTRACT_VERSIONS.includes(v.contractVersion)) {
    /* Unknown covenant/policy generation: fail closed, never default. */
    f.add("CONTRACT_VERSION_UNSUPPORTED", "subject.contractVersion", `unsupported covenant generation ${JSON.stringify(v.contractVersion)} — failing closed`);
  }
  decimal(f, v.policyNonce, "subject.policyNonce", { max: U64_MAX, allowNotAvailable: true });
  hex64(f, v.stateBefore, "subject.stateBefore", { nullable: true, allowNotAvailable: true });
  hex64(f, v.stateAfter, "subject.stateAfter", { nullable: true, allowNotAvailable: true });
}

function checkAction(f, v) {
  if (!exactKeys(f, v, "action", ["type", "highLevel", "role", "aboveThreshold"])) return;
  str(f, v.type, "action.type", { re: IDENT_RE });
  if (v.highLevel !== null) str(f, v.highLevel, "action.highLevel", { re: IDENT_RE });
  enumOf(f, v.role, "action.role", ROLES, { allowNotAvailable: true });
  bool(f, v.aboveThreshold, "action.aboveThreshold");
}

function checkAuthorization(f, v) {
  if (!exactKeys(f, v, "authorization", ["decision", "refusalCode", "intentManifestHash", "intentManifestVerdict", "signerVisibleDigest", "signerXOnly"])) return;
  enumOf(f, v.decision, "authorization.decision", DECISIONS);
  if (v.refusalCode !== null) str(f, v.refusalCode, "authorization.refusalCode", { re: IDENT_RE });
  hex64(f, v.intentManifestHash, "authorization.intentManifestHash", { allowNotAvailable: true });
  if (v.intentManifestVerdict !== NOT_AVAILABLE) enumOf(f, v.intentManifestVerdict, "authorization.intentManifestVerdict", MANIFEST_VERDICTS);
  hex64(f, v.signerVisibleDigest, "authorization.signerVisibleDigest", { allowNotAvailable: true });
  hex64(f, v.signerXOnly, "authorization.signerXOnly", { allowNotAvailable: true });
}

/*
 * APPROVALS — counts + public identities + per-approval DIGESTS.
 *
 * Justification for excluding raw signatures (task rule "never raw
 * signatures unless indispensable"): a collected M-of-N approval is a
 * 65-byte Schnorr signature over the frozen covenant input. Once the
 * transaction is broadcast that signature is PUBLIC on chain inside the
 * signature script, so the attestation gains no confidentiality by
 * omitting it — but it gains nothing evidentiary by carrying it either,
 * because the chain copy is authoritative and this record is not the
 * place to re-litigate consensus. sha256(signature) is enough to bind
 * "the approval I hold is the approval this attestation counted" for
 * anyone who legitimately holds the package, keeps the record small, and
 * removes a tempting mis-read of the record as a re-playable authority
 * artifact. Raw signatures are therefore NEVER carried.
 */
function checkApprovals(f, v) {
  if (!exactKeys(f, v, "approvals", ["required", "collected", "approverSlots", "packageCommitment", "approvalDigests"])) return;
  decimal(f, v.required, "approvals.required", { max: BigInt(MAX_APPROVER_SLOTS) });
  decimal(f, v.collected, "approvals.collected", { max: BigInt(MAX_APPROVER_SLOTS) });
  if (!Array.isArray(v.approverSlots) || v.approverSlots.length > MAX_APPROVER_SLOTS) {
    f.add("SCHEMA_INVALID", "approvals.approverSlots", `must be an array of at most ${MAX_APPROVER_SLOTS} x-only keys`);
  } else {
    v.approverSlots.forEach((s, i) => hex64(f, s, `approvals.approverSlots[${i}]`));
  }
  hex64(f, v.packageCommitment, "approvals.packageCommitment", { nullable: true });
  if (!Array.isArray(v.approvalDigests) || v.approvalDigests.length > MAX_APPROVER_SLOTS) {
    f.add("SCHEMA_INVALID", "approvals.approvalDigests", `must be an array of at most ${MAX_APPROVER_SLOTS} entries`);
    return;
  }
  v.approvalDigests.forEach((d, i) => {
    const p = `approvals.approvalDigests[${i}]`;
    if (!exactKeys(f, d, p, ["slot", "approverXOnly", "signatureDigest"])) return;
    decimal(f, d.slot, `${p}.slot`, { max: BigInt(MAX_APPROVER_SLOTS - 1) });
    hex64(f, d.approverXOnly, `${p}.approverXOnly`);
    hex64(f, d.signatureDigest, `${p}.signatureDigest`);
  });
}

function checkAsset(f, v) {
  if (!exactKeys(f, v, "asset", ["kind", "descriptorHash", "familyId", "unit"])) return;
  enumOf(f, v.kind, "asset.kind", ASSET_KINDS);
  hex64(f, v.descriptorHash, "asset.descriptorHash", { nullable: true });
  hex64(f, v.familyId, "asset.familyId", { nullable: true });
  enumOf(f, v.unit, "asset.unit", ASSET_UNITS);
  if (v.kind === "KAS" && (v.descriptorHash !== null || v.familyId !== null)) {
    f.add("ASSET_SHAPE_INVALID", "asset", "a KAS attestation carries no token descriptor/family identity");
  }
  if (v.kind === "KAS" && v.unit !== "sompi") f.add("ASSET_SHAPE_INVALID", "asset.unit", "KAS amounts are denominated in sompi");
  if (v.kind === "TOKEN" && v.unit !== "atomic") f.add("ASSET_SHAPE_INVALID", "asset.unit", "token amounts are denominated in atomic units");
}

function checkDestination(f, v) {
  if (!exactKeys(f, v, "destination", ["kind", "identity", "scriptHex"])) return;
  enumOf(f, v.kind, "destination.kind", DESTINATION_KINDS, { allowNotAvailable: true });
  if (v.identity !== null) str(f, v.identity, "destination.identity", { max: 200 });
  if (v.scriptHex !== null) {
    if (typeof v.scriptHex !== "string" || !HEX_RE.test(v.scriptHex) || v.scriptHex.length === 0 || v.scriptHex.length > 400) {
      f.add("SCHEMA_INVALID", "destination.scriptHex", "must be lowercase even-length hex (<=200 bytes) or null");
    }
  }
  if (v.kind === "NONE" && (v.identity !== null || v.scriptHex !== null)) {
    f.add("SCHEMA_INVALID", "destination", 'destination.kind "NONE" carries no identity/script');
  }
}

function checkAmounts(f, v) {
  if (!exactKeys(f, v, "amounts", ["amount", "networkFeeSompi", "protocolFeeSompi"])) return;
  decimal(f, v.amount, "amounts.amount", { max: U64_MAX, allowNotAvailable: true });
  decimal(f, v.networkFeeSompi, "amounts.networkFeeSompi", { allowNotAvailable: true });
  decimal(f, v.protocolFeeSompi, "amounts.protocolFeeSompi", { nullable: true });
}

function checkChain(f, v) {
  const keys = [
    "acceptingBlockDaaScore",
    "observedVirtualDaaScore",
    "depthDaa",
    "minDepthDaa",
    "predecessorOutpoint",
    "successorOutpoint",
    "successorStateId",
    "covenantId",
    "scriptSha256",
    "outputs"
  ];
  if (!exactKeys(f, v, "outcome.chain", keys)) return;
  decimal(f, v.acceptingBlockDaaScore, "outcome.chain.acceptingBlockDaaScore", { max: U64_MAX, nullable: true });
  decimal(f, v.observedVirtualDaaScore, "outcome.chain.observedVirtualDaaScore", { max: U64_MAX, nullable: true });
  decimal(f, v.depthDaa, "outcome.chain.depthDaa", { max: U64_MAX, nullable: true });
  decimal(f, v.minDepthDaa, "outcome.chain.minDepthDaa", { max: U64_MAX, nullable: true });
  outpoint(f, v.predecessorOutpoint, "outcome.chain.predecessorOutpoint", { nullable: true });
  outpoint(f, v.successorOutpoint, "outcome.chain.successorOutpoint", { nullable: true });
  hex64(f, v.successorStateId, "outcome.chain.successorStateId", { nullable: true });
  hex64(f, v.covenantId, "outcome.chain.covenantId", { nullable: true });
  hex64(f, v.scriptSha256, "outcome.chain.scriptSha256", { nullable: true });
  if (!Array.isArray(v.outputs) || v.outputs.length > MAX_CHAIN_OUTPUTS) {
    f.add("SCHEMA_INVALID", "outcome.chain.outputs", `must be an array of at most ${MAX_CHAIN_OUTPUTS} observed outputs`);
    return;
  }
  v.outputs.forEach((o, i) => {
    const p = `outcome.chain.outputs[${i}]`;
    if (!exactKeys(f, o, p, ["index", "address", "valueSompi", "covenantId", "blockDaaScore"])) return;
    if (!Number.isInteger(o.index) || o.index < 0 || o.index > 0xffff) f.add("SCHEMA_INVALID", `${p}.index`, "must be an integer 0..65535");
    str(f, o.address, `${p}.address`, { max: 200 });
    decimal(f, o.valueSompi, `${p}.valueSompi`);
    hex64(f, o.covenantId, `${p}.covenantId`, { nullable: true });
    decimal(f, o.blockDaaScore, `${p}.blockDaaScore`, { max: U64_MAX, nullable: true });
  });
}

function checkOutcome(f, v) {
  if (!exactKeys(f, v, "outcome", ["state", "disposition", "failureCode", "reached", "txId", "networkId", "chain"])) return;
  if (v.state !== "REFUSED") enumOf(f, v.state, "outcome.state", LADDER);
  enumOf(f, v.disposition, "outcome.disposition", DISPOSITIONS);
  if (v.failureCode !== null) str(f, v.failureCode, "outcome.failureCode", { re: IDENT_RE });
  hex64(f, v.txId, "outcome.txId", { nullable: true });
  str(f, v.networkId, "outcome.networkId", { re: NETWORK_RE });
  if (!Array.isArray(v.reached) || v.reached.length > LADDER.length) {
    f.add("SCHEMA_INVALID", "outcome.reached", `must be an array of at most ${LADDER.length} ladder entries`);
  } else {
    v.reached.forEach((r, i) => {
      const p = `outcome.reached[${i}]`;
      if (!exactKeys(f, r, p, ["state", "source", "note"])) return;
      enumOf(f, r.state, `${p}.state`, LADDER);
      str(f, r.source, `${p}.source`, { re: IDENT_RE });
      if (r.note !== null) str(f, r.note, `${p}.note`, { max: 300 });
    });
  }
  checkChain(f, v.chain);
}

function checkSignatureSlot(f, v) {
  if (v === null) return;
  if (!exactKeys(f, v, "signature", ["scheme", "keyId", "publicKey", "value", "signedAt"])) return;
  if (v.scheme !== SIGNATURE_SCHEME_1) {
    f.add("SIGNATURE_SCHEME_UNKNOWN", "signature.scheme", `unknown detached-signature scheme ${JSON.stringify(v.scheme)} — failing closed`);
    return;
  }
  str(f, v.keyId, "signature.keyId", { re: IDENT_RE });
  hex64(f, v.publicKey, "signature.publicKey");
  if (typeof v.value !== "string" || !/^[0-9a-f]{128}$/.test(v.value)) {
    f.add("SCHEMA_INVALID", "signature.value", "must be 64-byte lowercase hex (128 chars)");
  }
  str(f, v.signedAt, "signature.signedAt", { re: ISO_MS_RE });
}

/* ------------------------------------------------------------------ */
/* shape check over the whole record                                   */
/* ------------------------------------------------------------------ */

const BODY_KEYS = Object.freeze([
  "attestationVersion",
  "producedAt",
  "producer",
  "subject",
  "action",
  "authorization",
  "approvals",
  "asset",
  "destination",
  "amounts",
  "outcome"
]);
const RECORD_KEYS = Object.freeze([...BODY_KEYS, "attestationHash", "signature"]);

/*
 * Shape-only validation (no cross-field consistency, no hashing). Returns
 * a Failures accumulator so a caller can keep collecting.
 */
function checkShape(record, f = new Failures()) {
  if (!isPlainObject(record)) {
    f.add("SCHEMA_INVALID", "$", "attestation record must be a plain object");
    return f;
  }
  /* EXACT-MATCH VERSION FIRST: an unknown version is refused before any
   * other field is interpreted — never routed to a default reader. */
  if (record.attestationVersion !== ATTESTATION_VERSION_1) {
    f.add(
      "ATTESTATION_VERSION_UNSUPPORTED",
      "attestationVersion",
      `this verifier understands exactly ${ATTESTATION_VERSION_1}; got ${JSON.stringify(record.attestationVersion)} — failing closed`
    );
    return f;
  }
  if (!exactKeys(f, record, "$", RECORD_KEYS)) return f;
  str(f, record.producedAt, "producedAt", { re: ISO_MS_RE });
  hex64(f, record.attestationHash, "attestationHash");
  checkProducer(f, record.producer);
  checkSubject(f, record.subject);
  checkAction(f, record.action);
  checkAuthorization(f, record.authorization);
  checkApprovals(f, record.approvals);
  checkAsset(f, record.asset);
  checkDestination(f, record.destination);
  checkAmounts(f, record.amounts);
  checkOutcome(f, record.outcome);
  checkSignatureSlot(f, record.signature);
  return f;
}

module.exports = {
  ATTESTATION_VERSION_1,
  BATCH_VERSION_1,
  VERIFIER_VERSION_1,
  SIGNATURE_SCHEME_1,
  NOT_AVAILABLE,
  LADDER,
  LADDER_INDEX,
  DECISIONS,
  DISPOSITIONS,
  ROLES,
  ASSET_KINDS,
  ASSET_UNITS,
  DESTINATION_KINDS,
  MANIFEST_VERDICTS,
  SUPPORTED_CONTRACT_VERSIONS,
  SOMPI_PER_KAS,
  MAX_SOMPI,
  U64_MAX,
  MAX_APPROVER_SLOTS,
  MAX_CHAIN_OUTPUTS,
  BODY_KEYS,
  RECORD_KEYS,
  Failures,
  isPlainObject,
  checkShape
};
