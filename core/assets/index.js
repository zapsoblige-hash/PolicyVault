"use strict";

/*
 * core/assets — PUBLIC INTERFACE of the v0.5 asset layer of the shared
 * deterministic core (frozen design: docs/postlaunch/v0.5-design-freeze.md).
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/assets/test), production-byte
 * pinned to the real compiler/engine fixture. Imported by NO production
 * transaction path yet (v0.5 implementation phase); every consumer —
 * browser, mobile, server, CLI, self-host, MCP, x402, USI, SDK — must reuse
 * these functions rather than re-implement token semantics.
 *
 *   validateAssetDescriptor(d)          closed-schema descriptor validation
 *   computeDescriptorHash(d)            the hash a vault policy PINS
 *   corroborateTemplate({...})          descriptor template <-> real bytes
 *   verifyTokenInputRedeem({...})       raw revealed redeem -> verified state
 *   redeemFromSignatureScript(hex)      P2SH redeem = last push
 *   kcc20 / blake2b                     the underlying codecs (re-exported)
 *
 * Trust model: nothing here consults an indexer, server, UI, or label. A
 * descriptor is DATA until validated; template bytes are trusted only after
 * they hash to the pinned in-VM identity under the pinned geometry; a token
 * state is trusted only after its redeem matches an accepted template AND
 * (by the caller) the input's P2SH script public key.
 */

const crypto = require("crypto");
const { canonicalJsonStringify } = require("../model/canonical-json");
const descriptorModule = require("./descriptor");
const kcc20 = require("./kcc20");
const blake2b = require("./blake2b");

const { validateAssetDescriptor, DescriptorError, SCHEMA_V1 } = descriptorModule;

const DESCRIPTOR_HASH_DOMAIN = "policyvault-asset-descriptor-hash/1";

function fail(code, message) {
  throw new DescriptorError(code, message);
}

/* JSON body of a validated descriptor with NO undefined fields (canonical
 * JSON fails closed on undefined; optional fields are simply absent). */
function descriptorHashBody(validated) {
  const body = {
    schema: validated.schema,
    assetId: validated.assetId,
    displayName: validated.displayName,
    tokenStandard: validated.tokenStandard,
    tokenCovenantId: validated.tokenCovenantId,
    acceptedTransferTemplates: validated.acceptedTransferTemplates.map((t) => {
      const tpl = {
        templateVmHashBlake2b256: t.templateVmHashBlake2b256,
        prefixLen: t.prefixLen,
        suffixLen: t.suffixLen,
        stateLayout: t.stateLayout
      };
      if (t.templateKcc1HashBlake3 !== undefined) tpl.templateKcc1HashBlake3 = t.templateKcc1HashBlake3;
      return tpl;
    }),
    decimalsDisplay: validated.decimalsDisplay,
    issuerPowers: { ...validated.issuerPowers }
  };
  if (validated.notes !== undefined) body.notes = validated.notes;
  return body;
}

/*
 * The descriptor hash pinned into vault policy at acceptance
 * (downgrade/substitution refusal falls out of the pin). Domain-separated
 * sha256 over the canonical JSON of the VALIDATED descriptor, so key order,
 * whitespace, and non-semantic input variations never change it, while any
 * semantic change (a hash, a length, a power, the layout) does.
 */
function computeDescriptorHash(descriptor) {
  const validated = validateAssetDescriptor(descriptor);
  const canonical = canonicalJsonStringify(descriptorHashBody(validated));
  return crypto.createHash("sha256").update(`${DESCRIPTOR_HASH_DOMAIN}\n${canonical}`, "utf8").digest("hex");
}

function selectTemplate(validated, templateIndex) {
  if (!Number.isInteger(templateIndex) || templateIndex < 0 || templateIndex >= validated.acceptedTransferTemplates.length) {
    fail("DESCRIPTOR_MALFORMED", `templateIndex ${JSON.stringify(templateIndex)} is not an accepted template of this descriptor`);
  }
  return validated.acceptedTransferTemplates[templateIndex];
}

function geometryOf(tpl) {
  return kcc20.normalizeGeometry({ prefixLen: tpl.prefixLen, stateLen: kcc20.STATE_LEN, suffixLen: tpl.suffixLen });
}

/*
 * Deterministic corroboration of one accepted template against REAL
 * template bytes (issuer-published or sliced from a live UTXO's revealed
 * redeem): geometry, the in-VM blake2b identity, the standardness envelope.
 * Returns a frozen report; throws DescriptorError on any mismatch. The
 * KCC-0001 BLAKE3 identity, when declared, is carried as opaque
 * interoperability data — this core has no BLAKE3 and NEVER infers it from
 * the VM hash (frozen hash-semantics rule); its corroboration status is
 * reported explicitly as NOT_AVAILABLE, never silently as verified.
 */
function corroborateTemplate({ descriptor, templateIndex = 0, prefixHex, suffixHex }) {
  const validated = validateAssetDescriptor(descriptor);
  const tpl = selectTemplate(validated, templateIndex);
  const prefix = kcc20.hexToBytes(prefixHex ?? "", "prefixHex");
  const suffix = kcc20.hexToBytes(suffixHex ?? "", "suffixHex");
  const geometry = geometryOf(tpl);
  if (prefix.length !== geometry.prefixLen || suffix.length !== geometry.suffixLen) {
    fail(
      "TEMPLATE_GEOMETRY_MISMATCH",
      `template bytes are ${prefix.length}/${suffix.length} (prefix/suffix) but the descriptor pins ${geometry.prefixLen}/${geometry.suffixLen} — the unframed VM hash requires exact geometry; failing closed`
    );
  }
  const vmHash = kcc20.templateVmHashHex(prefix, suffix);
  if (vmHash !== tpl.templateVmHashBlake2b256) {
    fail("TEMPLATE_HASH_MISMATCH", "blake2b-256(prefix || suffix) does not equal the descriptor's templateVmHashBlake2b256 — failing closed");
  }
  const standardness = kcc20.templateStandardness(prefix, suffix);
  if (!standardness.standard) {
    fail(
      standardness.reason,
      standardness.reason === "TEMPLATE_MALFORMED"
        ? "template script does not parse — failing closed"
        : `template static P2SH sig-ops ${standardness.staticSigOps} exceed the standard limit ${standardness.limit} (family bound > 15) — this template must not become spend-enabled`
    );
  }
  return Object.freeze({
    ok: true,
    templateIndex,
    stateLayout: tpl.stateLayout,
    geometry,
    templateVmHashBlake2b256: vmHash,
    staticSigOps: standardness.staticSigOps,
    standardness: "STANDARD",
    kcc1Corroboration: tpl.templateKcc1HashBlake3 === undefined ? "NOT_DECLARED" : "NOT_AVAILABLE"
  });
}

/*
 * Canonical token parser for a RAW revealed redeem (e.g. the last push of a
 * token input's signature script): identifies the accepted template it
 * carries (geometry + in-VM hash; NEVER by label), decodes the state, and
 * returns the P2SH script public key the input MUST carry. The caller binds
 * the returned p2shSpkHex to the actual UTXO — a redeem that is not the
 * input's real script proves nothing.
 */
function verifyTokenInputRedeem({ descriptor, redeemHex }) {
  const validated = validateAssetDescriptor(descriptor);
  const redeem = kcc20.hexToBytes(redeemHex ?? "", "redeemHex");
  let matched = null;
  for (let i = 0; i < validated.acceptedTransferTemplates.length; i++) {
    const tpl = validated.acceptedTransferTemplates[i];
    const geometry = geometryOf(tpl);
    if (redeem.length !== geometry.prefixLen + geometry.stateLen + geometry.suffixLen) continue;
    const parts = kcc20.splitRedeem(redeem, geometry);
    if (kcc20.templateVmHashHex(parts.prefix, parts.suffix) !== tpl.templateVmHashBlake2b256) continue;
    matched = { templateIndex: i, geometry, parts, vmHash: tpl.templateVmHashBlake2b256 };
    break;
  }
  if (!matched) {
    fail("TEMPLATE_HASH_MISMATCH", "the revealed redeem matches none of the descriptor's accepted templates (geometry + in-VM hash) — failing closed");
  }
  const state = kcc20.decodeState(matched.parts.state);
  return Object.freeze({
    templateIndex: matched.templateIndex,
    templateVmHashBlake2b256: matched.vmHash,
    geometry: matched.geometry,
    prefixHex: kcc20.bytesToHex(matched.parts.prefix),
    suffixHex: kcc20.bytesToHex(matched.parts.suffix),
    state,
    p2shSpkHex: kcc20.p2shSpkHex(redeem)
  });
}

function redeemFromSignatureScript(sigscriptHex) {
  return kcc20.bytesToHex(kcc20.lastPushData(kcc20.hexToBytes(sigscriptHex ?? "", "sigscriptHex")));
}

module.exports = Object.freeze({
  SCHEMA_V1,
  DESCRIPTOR_HASH_DOMAIN,
  DescriptorError,
  Kcc20Error: kcc20.Kcc20Error,
  validateAssetDescriptor,
  parseAtomicAmount: descriptorModule.parseAtomicAmount,
  computeDescriptorHash,
  corroborateTemplate,
  verifyTokenInputRedeem,
  redeemFromSignatureScript,
  kcc20,
  blake2b
});
