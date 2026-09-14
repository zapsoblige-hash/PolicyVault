"use strict";

/*
 * ANY-GENERATION manifest loader for hosted TENANCY (rc11 internal security
 * review F-04, 2026-09-04).
 *
 * `sdk/src/manifest-v2.js loadAnyManifest` knows v1 / v2 / v4 and FAILS CLOSED
 * on every later schema. The Wave-2 surfaces (v0.5 / v0.6 token controllers,
 * v0.7 rooted vaults, the v0.7-payment-hd candidate) therefore had NO
 * participant derivation at all in server/src/tenancy.js — the root cause of
 * the audit's cross-tenant findings. This module reads the ONE durable vault
 * record and dispatches on its OWN schema tag to the generation's canonical
 * normalizer, returning the same `{ version, manifest }` shape tenancy.js
 * consumes, with these version tags:
 *   "v1" | "v2" | "v4"  (unchanged, via loadAnyManifest)
 *   "v5" | "v6"         token controllers   (template.owner + agentRegistry)
 *   "v7"                rooted vault        (agentRegistry; owners = the org root)
 *   "v7hd"              rooted HD vault     (delegation forest leaves; owners = the org root)
 *   "v7kas"             rooted KAS vault    (v0.4.1 agent registry + vault-level approver slots; owners = the org root)
 * Unknown schemas fail closed (no default route). Never guesses.
 */

const { getStore, Categories } = require("../../sdk/src/store");
const { loadAnyManifest } = require("../../sdk/src/manifest-v2");

const SCHEMA_V5 = "policyvault-token-controller-manifest/v5";
const SCHEMA_V6 = "policyvault-controller-manifest/v6";
const SCHEMA_V7 = "policyvault-rooted-vault-manifest-record/1";
const SCHEMA_V7_HD = "policyvault-rooted-hd-vault-manifest-record/1";
const SCHEMA_V7_KAS = "policyvault-rooted-kas-vault-manifest-record/1"; // v0.7 enablement (2026-09-10): rooted KAS safe-payment vault (CANDIDATE)

async function loadAnyManifestAll(config, vaultId) {
  const raw = await getStore(config).read(Categories.VAULT, vaultId);
  if (raw === null || raw === undefined) return null;
  const tag = typeof raw.schema === "string" ? raw.schema : typeof raw.manifestVersion === "string" ? raw.manifestVersion : null;
  if (tag === SCHEMA_V5) {
    const { loadManifestV5 } = require("../../sdk/src/manifest-v5");
    const manifest = await loadManifestV5(config, vaultId);
    return manifest ? { version: "v5", manifest } : null;
  }
  if (tag === SCHEMA_V6) {
    const { loadManifestV6 } = require("../../sdk/src/manifest-v6");
    const manifest = await loadManifestV6(config, vaultId);
    return manifest ? { version: "v6", manifest } : null;
  }
  if (tag === SCHEMA_V7) {
    const { loadManifestV7 } = require("../../sdk/src/manifest-v7");
    const manifest = await loadManifestV7(config, vaultId);
    return manifest ? { version: "v7", manifest } : null;
  }
  if (tag === SCHEMA_V7_HD) {
    const { loadManifestV7Hd } = require("../../sdk/src/manifest-v7-hd");
    const manifest = await loadManifestV7Hd(config, vaultId);
    return manifest ? { version: "v7hd", manifest } : null;
  }
  if (tag === SCHEMA_V7_KAS) {
    const { loadManifestV7Kas } = require("../../sdk/src/manifest-v7-kas");
    const manifest = await loadManifestV7Kas(config, vaultId);
    return manifest ? { version: "v7kas", manifest } : null;
  }
  // v1 / v2 / v4 (fails closed on anything it does not know)
  return loadAnyManifest(config, vaultId);
}

module.exports = { loadAnyManifestAll, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, SCHEMA_V7_HD, SCHEMA_V7_KAS };
