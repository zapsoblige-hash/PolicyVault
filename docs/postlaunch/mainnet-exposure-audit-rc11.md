# Mainnet covenant-generation exposure audit (rc11 pre-promotion gate)

Owner pre-promotion gate, 2026-09-04. Mechanical trace of the rc11 source
(flagship-wave2). NON-PRODUCTION audit — nothing deployed. Hard owner rule:
UNFROZEN CANDIDATES MUST NOT BE MAINNET-CREATABLE OR MAINNET-MUTABLE; a byte
freeze does NOT by itself authorize mainnet creation; v0.6 real swap must
remain disabled.

## 1. Exposure matrix (rc11 source, BEFORE remediation `8a82e11`)

Traced: server routes, capability advertisement, SDK dispatch, MCP tools,
web modules, `assertOperationalNetwork` (dual-flag only), config flags.
"Mainnet create/mutate" = a mainnet-configured server with the Gate-R dual
flag (`POLICYVAULT_ALLOW_MAINNET` + explicit mainnet RPC), which is the live
production posture.

| generation | status | discover/read | create | build mutation | submit/broadcast | reconcile | reachable via | mainnet create/mutate (as prepared) |
|---|---|---|---|---|---|---|---|---|
| v0.4.1 | FROZEN, LIVE | `/vaults`, `/wallet/v4/*`, caps | `/wallet/v4` | `/wallet/v4/requests` | `.../submit` | `/vaults/:id/reconcile` | API/MCP/web | **YES — the Gate-R production generation (authorized)** |
| v0.5 | FROZEN | caps, `/wallet/v5/*` | `/wallet/v5/create` | `/wallet/v5/requests` | `.../submit` | reconcile-v5 | API/web | YES (only `assertOperationalNetwork`) — NOT owner-authorized |
| v0.6 | FROZEN (FIXTURE) | caps, `/wallet/v6/*` | `/wallet/v6/create` | `/wallet/v6/requests` | `.../submit` | reconcile-v6 | API/web | Controller/token ops YES; **REAL SWAP BLOCKED** (`VENUE_PROFILE_UNSUPPORTED`, fixture only) — NOT owner-authorized |
| v0.7-root | FROZEN | `/org-roots`, caps | `POST /org-roots` | `/org-roots/:id/requests` | `.../submit` | `/org-roots/:id/reconcile` | API/MCP/web | YES — NOT owner-authorized (freeze ≠ mainnet org) |
| v0.7-payment | FROZEN | `/org-roots/:id/vaults`, caps | `POST /org-roots/:id/vaults` (profile) | `/wallet/v7/requests` | `.../submit` | reconcile | API/MCP/web | YES — NOT owner-authorized |
| **v0.7-kas** | **CANDIDATE (unfrozen)** | not advertised; NO server route | **none** | none | none | none | CLI tools only | **NO via product surface — safe** |
| **v0.7-payment-hd** | **CANDIDATE (unfrozen)** | caps `status: CANDIDATE`, `/org-roots/:id/vaults`, `/wallet/v7/requests` | `POST /org-roots/:id/vaults` (profile `policyvault-0.7-payment-hd`) | `/wallet/v7/requests` (HD actions); MCP `policyvault_create_v7_request` | `.../submit` | reconcile | **API + MCP + web** | **YES — HARD-RULE VIOLATION (before remediation)** |

## 2. Finding + remediation

**Finding (accidental exposure):** rc11 as prepared would let a mainnet
user create/mutate the UNFROZEN v0.7-payment-hd (HD) candidate on mainnet.
- Exact reachable routes: `POST /org-roots/:rootId/vaults` with
  `profile: "policyvault-0.7-payment-hd"` (genesis); `POST /wallet/v7/requests`
  and MCP `policyvault_create_v7_request` (HD delegate spend / deposit);
  their `.../submit`.
- Exact generation: `policyvault-0.7-payment-hd` (also v0.5/v0.6/v0.7-root/
  v0.7-payment were mainnet-creatable although frozen — byte-freeze ≠
  authorization).
- Exact authority exposed: on-chain creation of a rooted HD vault and
  delegate spends moving real KAS/token value under an unfrozen candidate
  covenant.
- Reachable via: API, MCP, and web (all three).
- Root cause: `sdk/src/config.js assertOperationalNetwork` checks only the
  dual-flag; no per-generation mainnet-authorization gate existed.

**Remediation (`8a82e11`, fail-closed, testnet unaffected):**
`assertGenerationMainnetCreatable(config, contractVersion)` — on mainnet
ONLY `policyvault-0.4`/`0.4.1` may be created/mutated; every other
generation throws `GENERATION_NOT_MAINNET_AUTHORIZED`. Wired at all 14
create/build/submit entries of wallet-requests-v5/v6/v7/v7-hd. Regression
gate `sdk/test/mainnet-generation-authorization.test.js` (4/4). v0.7-kas
already had no reachable product entry.

## 3. v0.6 real swap / DEX

Real-venue swaps are refused at build regardless of network:
`sdk/src/vault-builders-v6.js` / `swap-policy-v6.js` accept ONLY the
PolicyVault FIXTURE venue; any other venue → `VENUE_PROFILE_UNSUPPORTED`.
On mainnet the generation gate now also refuses any v0.6 create/mutate. So
mainnet real swap is disabled two ways over.

## 4. Frozen generations — smallest explicit mainnet-enablement gate

For v0.5 and frozen v0.7-root/v0.7-payment, current mainnet behavior AFTER
remediation is: REFUSED (`GENERATION_NOT_MAINNET_AUTHORIZED`). The smallest
explicit enablement gate the owner would use to authorize one later is to
add its exact contract-version string to
`MAINNET_CREATABLE_GENERATIONS` in `sdk/src/config.js` (a deliberate,
reviewable per-generation edit) — never inferred from a byte freeze, a green
gate, or a config flag. Gate R authorized mainnet OPERATION for the v0.4.x
generation only; it does not extend to later generations.

## 5. Residual (non-exposure) note

The public capabilities document still advertises v0.5/v0.6/v0.7 as routed
regardless of network; on mainnet a create attempt now fails closed with
`GENERATION_NOT_MAINNET_AUTHORIZED`. This is fail-closed (discovery is not
authority), but a future refinement could annotate each version's
mainnet-creatable status in the discovery document. Not an exposure.
