"use strict";

/*
 * Asset registry (decision G / OQ-F4): `KAS` (native, sompi) or
 * `pvad1:<descriptor-hash>` for a v0.5 `policyvault-asset-descriptor/1`
 * loaded from the facilitator's CONFIGURATION. No blessed list, no
 * payer-supplied descriptors, no indexer: a descriptor is accepted only
 * if it validates through core/assets and its recomputed hash equals BOTH
 * the configured pin and the literal. Everything else fails closed.
 */

const fs = require("node:fs");
const assets = require("../../core/assets");
const { ASSET_KAS, ASSET_DESCRIPTOR_PREFIX } = require("./constants");
const { refuse } = require("./codes");

const HASH_RE = /^[0-9a-f]{64}$/;

class AssetRegistry {
  /* entries: [{ descriptorHash, file? | descriptor? }] */
  constructor(entries = []) {
    this.tokens = new Map();
    if (!Array.isArray(entries)) throw new Error("x402-facilitator: descriptor allowlist must be an array");
    for (const entry of entries) {
      if (!entry || typeof entry !== "object") throw new Error("x402-facilitator: descriptor allowlist entry must be an object");
      if (typeof entry.descriptorHash !== "string" || !HASH_RE.test(entry.descriptorHash)) {
        throw new Error("x402-facilitator: descriptor allowlist entry requires descriptorHash (64 lowercase hex) — fail closed");
      }
      let descriptor = entry.descriptor;
      if (descriptor === undefined) {
        if (typeof entry.file !== "string" || !entry.file) throw new Error("x402-facilitator: descriptor allowlist entry requires descriptor or file");
        descriptor = JSON.parse(fs.readFileSync(entry.file, "utf8"));
      }
      let validated;
      let hash;
      try {
        validated = assets.validateAssetDescriptor(descriptor);
        hash = assets.computeDescriptorHash(descriptor);
      } catch (e) {
        throw new Error(`x402-facilitator: configured descriptor ${entry.descriptorHash.slice(0, 12)}… is invalid (${e.code ?? "?"}: ${e.message}) — fail closed`);
      }
      if (hash !== entry.descriptorHash) {
        throw new Error(`x402-facilitator: configured descriptor hash ${entry.descriptorHash.slice(0, 12)}… does not equal the recomputed hash ${hash.slice(0, 12)}… — fail closed`);
      }
      const literal = `${ASSET_DESCRIPTOR_PREFIX}${hash}`;
      if (this.tokens.has(literal)) throw new Error(`x402-facilitator: descriptor ${hash.slice(0, 12)}… configured twice`);
      this.tokens.set(literal, Object.freeze({ kind: "TOKEN", literal, descriptorHash: hash, descriptor: validated }));
    }
  }

  /* Exact literal lookup; anything else → ASSET_UNSUPPORTED. */
  resolve(literal) {
    if (literal === ASSET_KAS) return Object.freeze({ kind: ASSET_KAS, literal: ASSET_KAS });
    if (typeof literal === "string" && this.tokens.has(literal)) return this.tokens.get(literal);
    refuse("ASSET_UNSUPPORTED", typeof literal === "string" ? literal.slice(0, 80) : String(literal));
  }

  list() {
    return Object.freeze([ASSET_KAS, ...this.tokens.keys()]);
  }
}

module.exports = { AssetRegistry };
