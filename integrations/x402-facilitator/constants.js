"use strict";

/*
 * FROZEN constants of the PolicyVault x402 facilitator — the identities
 * pinned by docs/postlaunch/x402-facilitator-design-freeze.md ("X402
 * FACILITATOR DESIGN FREEZE — OWNER AUTHORIZED + COMPLETE", 2026-09-02)
 * and guarded by integrations/test/x402f-design-freeze.test.js. Changing
 * any value here is a NEW scheme / policy / profile version or an
 * owner-authorized freeze reopen — never an in-place edit.
 */

const X402_VERSION = 2;
const SCHEME = "exact";
const PAYMENT_FLOW = "upfront";
const KASPA_SCHEME_ID = "pv-x402-kaspa-exact-upfront/1";
const SETTLEMENT_POLICY_ID = "pv-x402-settlement/1";

/* Decision A (OQ-F1): default 100, HARD FLOOR 20 (20 is never the target). */
const MIN_DEPTH_DAA_DEFAULT = 100n;
const MIN_DEPTH_DAA_FLOOR = 20n;
/* Decision B (OQ-F2). */
const MAX_WINDOW_DAA = 36000n;

/*
 * OQ-F3: PolicyVault's PROVISIONAL Kaspa network identifiers in CAIP-2
 * syntax / profile form. The Kaspa namespace is NOT claimed to be an
 * upstream-registered CAIP-2 namespace. Exact strings only; the kaspad
 * networkId on the right is what the node MUST report on every
 * observation (testnet-10 by explicit netsuffix — no testnet is
 * equivalent to another).
 */
const NETWORKS = Object.freeze({
  "kaspa:mainnet": Object.freeze({ identifier: "kaspa:mainnet", kaspadNetworkId: "mainnet", addressPrefix: "kaspa" }),
  "kaspa:testnet-10": Object.freeze({ identifier: "kaspa:testnet-10", kaspadNetworkId: "testnet-10", addressPrefix: "kaspatest" })
});
const NETWORK_IDENTIFIERS = Object.freeze(Object.keys(NETWORKS));

/* Decision G (OQ-F4). */
const ASSET_KAS = "KAS";
const ASSET_DESCRIPTOR_PREFIX = "pvad1:";

const EVIDENCE_SCHEMA = "policyvault-x402-facilitator-evidence/1";
const REQUIREMENT_DIGEST_DOMAIN = "policyvault-x402-facilitator-requirement/1";
const EVIDENCE_DIGEST_DOMAIN = "policyvault-x402-facilitator-evidence/1";

/* OQ-F7: dedicated facilitator credential format (never pvmk_, never a session). */
const CREDENTIAL_PREFIX = "pvx402f_";
const CREDENTIAL_RE = /^pvx402f_[0-9a-f]{64}$/;
const PRINCIPAL_OPERATIONS = Object.freeze(["verify", "settle"]);

module.exports = Object.freeze({
  X402_VERSION,
  SCHEME,
  PAYMENT_FLOW,
  KASPA_SCHEME_ID,
  SETTLEMENT_POLICY_ID,
  MIN_DEPTH_DAA_DEFAULT,
  MIN_DEPTH_DAA_FLOOR,
  MAX_WINDOW_DAA,
  NETWORKS,
  NETWORK_IDENTIFIERS,
  ASSET_KAS,
  ASSET_DESCRIPTOR_PREFIX,
  EVIDENCE_SCHEMA,
  REQUIREMENT_DIGEST_DOMAIN,
  EVIDENCE_DIGEST_DOMAIN,
  CREDENTIAL_PREFIX,
  CREDENTIAL_RE,
  PRINCIPAL_OPERATIONS
});
