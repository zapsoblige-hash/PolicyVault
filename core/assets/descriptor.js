"use strict";

/*
 * v0.5 ASSET DESCRIPTOR — DESIGN-STAGE DRAFT (D1 item 1; 2026-09-01).
 *
 * STATUS: NOT PRODUCTION. No production path imports this module; it is
 * the reference validator for the v0.5 per-asset descriptor schema and
 * exists so the design gate can review executable, tested semantics
 * instead of prose. The v0.5 design-freeze gate decides adoption; until
 * then the schema may change without migration duty.
 *
 * WHAT A DESCRIPTOR IS. The canonical, shared-deterministic-core record
 * that tells every PolicyVault surface (browser, mobile, server, CLI,
 * self-host, MCP, x402, USI, SDK) what a token asset IS and how a
 * transition involving it must verify. Per the 2026-08-31 architecture
 * addendum: descriptors live HERE in the core; no framework adapter,
 * hosted service, indexer, or UI may re-implement or override these
 * semantics; nothing a descriptor does not carry can be assumed.
 *
 * DUAL BINDING (addendum §3, VM-PROVEN by the V5 probes). A descriptor
 * carries BOTH bindings, and a transition must satisfy BOTH:
 *   1. tokenCovenantId  — WHO/what controller family is authorized
 *      (KIP-20 covenant lineage identity);
 *   2. acceptedTransferTemplates — WHICH bytes may carry the asset
 *      (hash-verified template pinning of the continuation outputs).
 * Either binding failing fails closed. Covenant-ID alone is NEVER
 * sufficient.
 *
 * HASH-CONVENTION DISCIPLINE (never conflate; both may be present):
 *   - templateVmHashBlake2b256: blake2b-256 over (prefix || suffix) —
 *     the identity the IN-VM `*WithTemplate` helpers verify at
 *     consensus (SOURCE-VERIFIED upstream; exercised by the V5 probe).
 *   - templateKcc1HashBlake3: BLAKE3-256 over
 *     LE64(len(prefix))||prefix||LE64(len(suffix))||suffix — the
 *     KCC-0001 convention-level template identity used by ecosystem
 *     tooling/registries (SPEC-VERIFIED).
 *   Each accepted template names BOTH values explicitly; nothing ever
 *   infers one from the other, and a descriptor with only one is valid
 *   ONLY for the uses that hash serves (in-VM pinning requires the
 *   blake2b value; ecosystem interop requires the KCC-0001 value).
 *
 * ISSUER POWERS ARE TRUST PROPERTIES, NOT GUARANTEES. `issuerPowers`
 * declares what the issuing covenant retains (mint/burn/freeze/...).
 * PolicyVault enforces spending policy deterministically REGARDLESS,
 * but it cannot remove powers intrinsic to the asset; explain output,
 * UI, compliance exports, and MCP responses must surface these
 * verbatim and never market an issuer-controlled asset as trustless.
 *
 * TWO ACCOUNTING DOMAINS. Token amounts here are integer atomic-unit
 * decimal STRINGS (same numeric discipline as sompi); they are NEVER
 * KAS. KAS fee-reserve accounting is a separate domain: nothing in a
 * descriptor can authorize spending token value as fees or charging
 * token budgets for KAS costs.
 *
 * NO BLESSED LIST. Descriptors are data an OWNER accepts per vault
 * policy (D2 onboarding design). The core may ship verified standard
 * descriptors as conveniences; acceptance is always an explicit owner
 * decision, and KAS-only vaults never migrate implicitly.
 *
 * FAIL-CLOSED RULES. Unknown schema version -> refuse. Unknown field ->
 * refuse (closed schema). Unknown enum value -> refuse. Missing
 * required binding -> refuse. Malformed hex/amount -> refuse.
 */

const SCHEMA_V1 = "policyvault-asset-descriptor/1";

/* Enumerations are CLOSED: an unlisted value refuses. */
const TOKEN_STANDARDS = Object.freeze(["kcc20/1"]);
const ISSUER_POWER_NAMES = Object.freeze([
  "mint",
  "burn",
  "freeze",
  "blacklist",
  "redemptionControl",
  "upgradeMigration",
  "controllerRotation",
  "emergencyControl"
]);

const HEX32 = /^[0-9a-f]{64}$/;
const HEX_EVEN = /^(?:[0-9a-f]{2})+$/;
/* Atomic-unit decimal string: no signs, no leading zeros (except "0"). */
const ATOMIC_DECIMAL = /^(0|[1-9][0-9]*)$/;

class DescriptorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DescriptorError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new DescriptorError(code, message);
}

function requireClosedObject(value, allowedKeys, where) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("DESCRIPTOR_MALFORMED", `${where} must be a plain object — failing closed`);
  }
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) {
      fail("DESCRIPTOR_UNKNOWN_FIELD", `${where} carries unknown field ${JSON.stringify(key)} — closed schema, failing closed`);
    }
  }
}

function requireHex32(value, where) {
  if (typeof value !== "string" || !HEX32.test(value)) {
    fail("DESCRIPTOR_MALFORMED", `${where} must be 64 lowercase hex characters — failing closed`);
  }
}

/*
 * validateAssetDescriptor(descriptor) -> frozen normalized descriptor.
 * Throws DescriptorError on ANY deviation. Never mutates its input.
 */
function validateAssetDescriptor(descriptor) {
  requireClosedObject(
    descriptor,
    [
      "schema",
      "assetId",
      "displayName",
      "tokenStandard",
      "tokenCovenantId",
      "acceptedTransferTemplates",
      "decimalsDisplay",
      "issuerPowers",
      "notes"
    ],
    "descriptor"
  );

  if (descriptor.schema !== SCHEMA_V1) {
    fail(
      "DESCRIPTOR_UNKNOWN_VERSION",
      `unknown descriptor schema ${JSON.stringify(descriptor.schema)} — unknown versions fail closed, never route to a default`
    );
  }

  requireHex32(descriptor.assetId, "assetId");
  requireHex32(descriptor.tokenCovenantId, "tokenCovenantId (BINDING 1: controller/covenant authorization)");

  if (typeof descriptor.displayName !== "string" || !descriptor.displayName.trim() || descriptor.displayName.length > 64) {
    fail("DESCRIPTOR_MALFORMED", "displayName must be a non-empty string of at most 64 characters — failing closed");
  }

  if (!TOKEN_STANDARDS.includes(descriptor.tokenStandard)) {
    fail(
      "DESCRIPTOR_UNKNOWN_STANDARD",
      `unknown tokenStandard ${JSON.stringify(descriptor.tokenStandard)} — unknown semantics fail closed`
    );
  }

  const templates = descriptor.acceptedTransferTemplates;
  if (!Array.isArray(templates) || templates.length === 0) {
    fail(
      "DESCRIPTOR_MISSING_BINDING",
      "acceptedTransferTemplates must be a non-empty array (BINDING 2: hash-verified template pinning) — covenant-ID alone is never sufficient"
    );
  }
  const normalizedTemplates = templates.map((tpl, i) => {
    const where = `acceptedTransferTemplates[${i}]`;
    requireClosedObject(
      tpl,
      ["templateVmHashBlake2b256", "templateKcc1HashBlake3", "prefixLen", "suffixLen", "stateLayout"],
      where
    );
    /* At least the IN-VM hash is required for a spendable binding; the
     * KCC-0001 hash is required alongside it for ecosystem interop and
     * may not substitute for it. */
    requireHex32(tpl.templateVmHashBlake2b256, `${where}.templateVmHashBlake2b256 (in-VM blake2b(prefix||suffix) identity)`);
    if (tpl.templateKcc1HashBlake3 !== undefined) {
      requireHex32(tpl.templateKcc1HashBlake3, `${where}.templateKcc1HashBlake3 (KCC-0001 BLAKE3/LE64-framed identity)`);
    }
    for (const lenField of ["prefixLen", "suffixLen"]) {
      const v = tpl[lenField];
      if (!Number.isInteger(v) || v < 0 || v > 100_000) {
        fail("DESCRIPTOR_MALFORMED", `${where}.${lenField} must be an integer 0..100000 — failing closed`);
      }
    }
    if (tpl.stateLayout !== "kcc20-state/1") {
      fail("DESCRIPTOR_UNKNOWN_STANDARD", `${where}.stateLayout ${JSON.stringify(tpl.stateLayout)} unknown — failing closed`);
    }
    return Object.freeze({ ...tpl });
  });

  const decimals = descriptor.decimalsDisplay;
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    fail(
      "DESCRIPTOR_MALFORMED",
      "decimalsDisplay must be an integer 0..18 — DISPLAY metadata only (KCC20 has no consensus decimals; amounts stay atomic-unit strings)"
    );
  }

  const powers = descriptor.issuerPowers;
  requireClosedObject(powers, ISSUER_POWER_NAMES.slice(), "issuerPowers");
  const normalizedPowers = {};
  for (const name of ISSUER_POWER_NAMES) {
    const v = powers[name];
    if (typeof v !== "boolean") {
      fail(
        "DESCRIPTOR_MALFORMED",
        `issuerPowers.${name} must be explicitly true or false — issuer powers are declared trust properties; omission is not deniability`
      );
    }
    normalizedPowers[name] = v;
  }

  if (descriptor.notes !== undefined && (typeof descriptor.notes !== "string" || descriptor.notes.length > 2000)) {
    fail("DESCRIPTOR_MALFORMED", "notes must be a string of at most 2000 characters when present");
  }

  return Object.freeze({
    schema: SCHEMA_V1,
    assetId: descriptor.assetId,
    displayName: descriptor.displayName,
    tokenStandard: descriptor.tokenStandard,
    tokenCovenantId: descriptor.tokenCovenantId,
    acceptedTransferTemplates: Object.freeze(normalizedTemplates),
    decimalsDisplay: decimals,
    issuerPowers: Object.freeze(normalizedPowers),
    notes: descriptor.notes
  });
}

/* Parse a token atomic-unit amount string (NEVER KAS/sompi — separate
 * accounting domain). Same rejection discipline as the sompi parsers. */
function parseAtomicAmount(value) {
  if (typeof value !== "string" || !ATOMIC_DECIMAL.test(value)) {
    fail("DESCRIPTOR_MALFORMED", "token amounts are non-negative atomic-unit decimal strings (no signs, no leading zeros) — failing closed");
  }
  const n = BigInt(value);
  if (n > 0xffffffffffffffffn) {
    fail("DESCRIPTOR_MALFORMED", "token amount exceeds u64 — failing closed");
  }
  return n;
}

module.exports = {
  SCHEMA_V1,
  TOKEN_STANDARDS,
  ISSUER_POWER_NAMES,
  DescriptorError,
  validateAssetDescriptor,
  parseAtomicAmount
};
