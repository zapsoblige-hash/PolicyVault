# PolicyVault x402 FACILITATOR (`integrations/x402-facilitator/`)

**Claim labels (exact, never collapsed): DESIGNED + DESIGN FROZEN (owner,
2026-09-02) · IMPLEMENTED · UNIT-TESTED · ADVERSARIAL-TESTED (hostile
matrix) · INTEGRATION-TESTED (real HTTP service, real PostgreSQL claim
store) · LIVE-TESTNET status: see `docs/postlaunch/x402-facilitator-program.md`
§3.** NOT PRODUCTION-HARDENED as a hosted service. No hosted deployment is authorized by this code
existing; that is a separate owner gate.

## What it is

The smallest possible x402 facilitator for Kaspa: a **separately
deployed, unprivileged, READ-ONLY chain verification / settlement
attestation service** for the proposed Kaspa scheme `exact` +
`extra.paymentFlow: "upfront"` (`pv-x402-kaspa-exact-upfront/1`). The
payer settles FIRST with an ordinary on-chain Kaspa transaction; the
facilitator only checks, against a synced UTXO-indexed node it trusts,
that the exact outpoint the payer names pays exactly the required amount
to exactly the required destination inside the requirement's DAA window
at the policy's settlement depth — and, on `/settle`, records ONE durable
single-use claim with the evidence.

It holds **no keys, signs nothing, broadcasts nothing, escrows nothing,
nets nothing, converts nothing, never calls a PolicyVault API, never
emits a 402, and never charges** (free forever). Its complete absence
costs PolicyVault nothing.

AI MAY REQUEST · POLICYVAULT DETERMINISTICALLY DECIDES · THE COVENANT
ENFORCES · SIGNERS RETAIN CUSTODY — the facilitator sits on the *resource
server's* side of the wire and adds a verification service; it never
moves any spend decision out of the payer's PolicyVault pipeline.

Frozen design: `docs/postlaunch/x402-facilitator-spec.md` (revision 3) and
`docs/postlaunch/x402-facilitator-design-freeze.md`; pinned by
`integrations/test/x402f-design-freeze.test.js`.

## Endpoints (x402 facilitator API shape)

| route | auth | does |
|---|---|---|
| `GET /supported` | public | the ONE kind this deployment verifies (`network`, assets, `pv-x402-settlement/1`); `signers` is `{}` |
| `GET /healthz` | public | liveness only (never touches the node) |
| `POST /verify` | resource-server credential | deterministic check; `isValid: true` ⇔ CHAIN_VERIFIED; **never writes state** |
| `POST /settle` | resource-server credential with `settle` authority | the same check + an atomic single-use claim + evidence; idempotent replay returns the same stored evidence |

Body for `/verify` and `/settle`: `{ "x402Version": 2, "paymentPayload": PaymentPayload, "paymentRequirements": PaymentRequirements }`
(closed Kaspa profile, spec §2). Every response is JSON with a code from
the CLOSED set (`codes.js`: 5 RETRY · 2 PENDING · 24 REFUSE · 4 AUTH).

Request order on the authenticated routes is fixed: query-string refusal
→ credential (401) → operation scope (403) → per-principal rate limit
(429) → body cap (413) → facilitator. An unauthenticated request never
reaches the body parser, the store, or the node.

## Network identifiers (OQ-F3, frozen)

`kaspa:mainnet` and `kaspa:testnet-10` — PolicyVault's PROVISIONAL Kaspa
identifiers in CAIP-2 syntax. The Kaspa namespace is **not** claimed to
be an upstream-registered CAIP-2 namespace. The string is never chain
evidence: the node's real network identity is verified on every
observation and disagreement fails closed.

## Resource-server credentials (OQ-F7, frozen for v1)

Facilitator-issued API key over HTTPS (`Authorization: Bearer pvx402f_…`),
bound to a dedicated principal (`principals.js`): operations (`verify`,
`settle`), networks, allowed `payTo` destinations (explicit list or
explicit "any"), optional resource origins, optional expiry, rotation
with overlap, immediate revocation. Raw credentials are 256-bit CSPRNG
values shown once at mint; only `sha256(raw)` is stored; comparison is
constant-time. They are NOT PolicyVault sessions or `pvmk_` machine
credentials and grant ZERO PolicyVault authority. mTLS is optional
future hardening, not part of v1.

```
PV_X402F_DATA_DIR=/var/lib/pv-x402f node integrations/x402-facilitator/bin/x402-facilitator-admin.js \
  principal create --id merchant-a --networks kaspa:testnet-10 --operations verify,settle --payto kaspatest:…
PV_X402F_DATA_DIR=/var/lib/pv-x402f node integrations/x402-facilitator/bin/x402-facilitator-admin.js \
  credential mint --principal merchant-a          # prints the raw credential ONCE on stdout
```

## Running

```
PV_X402F_NETWORK=kaspa:testnet-10 PV_X402F_RPC_URL=ws://127.0.0.1:18210 \
PV_X402F_DATA_DIR=/var/lib/pv-x402f node integrations/x402-facilitator/bin/x402-facilitator.js
```

Configuration is environment-only and closed (`config.js`): the network
identifier (required, no default), a PRIVATE node URL (loopback / RFC 1918
/ single-label host; public nodes refused), `PV_X402F_MIN_DEPTH_DAA`
(default 100; HARD FLOOR 20), the data directory, `PV_X402F_STORE`
(`json` single-instance store, or `postgres` — REQUIRED before any second
instance), `PV_X402F_DESCRIPTORS` (a JSON allowlist of v0.5 asset
descriptors pinned by hash; no blessed list), listen host/port (loopback
by default; a non-loopback bind requires `PV_X402F_ALLOW_NON_LOOPBACK=1`
behind a TLS-terminating proxy), rate limit, node timeout. Mainnet
additionally requires `POLICYVAULT_ALLOW_MAINNET=true` **and**
`--allow-mainnet` (dual unlock) and remains a separate owner deployment
gate.

## Token payments (frozen v0.5 semantics)

`asset: "pvad1:<descriptor-hash>"` — a `policyvault-asset-descriptor/1`
from the configured allowlist only. BOTH bindings are required: the
observed UTXO entry's consensus `covenantId` must equal the descriptor's
token family (WHO), and the payer-supplied redeem must hash to the
observed P2SH script, corroborate an accepted template (geometry, in-VM
hash, standardness) and decode to `kcc20-state/1` with owner == `payTo`
and amount == required (WHICH). Every token operation is a call into
`core/assets` — no x402-specific token parser exists. `transactionHex`
(hex of the wasm safe-JSON serialization) and `outputRedeems` are
mandatory; the txid is recomputed through the engine; the supplied
signature scripts are consistency data only (the Kaspa txid does not
commit to them) — the conservation check can refuse, never accept.

## Layout

```
constants.js   frozen identities (pin-tested)      codes.js       closed reason codes
network.js     identifier ↔ node identity          policy.js      pv-x402-settlement/1
schema.js      closed-schema intake + digest       assets.js      KAS + descriptor allowlist
carriage.js    transactionHex decode + txid        verify-kas.js  §7.1
verify-token.js §7.2 (core/assets)                 claims.js      JSON (link(2) create-exclusive) + PostgreSQL stores
principals.js  resource-server credentials         node.js        read-only node session
facilitator.js orchestration                        service.js     HTTP surface
bin/           launcher + admin CLI
```

Dependency direction (`integrations/test/dependency-direction.test.js`
rule 5): only `core/**`, `integrations/lib/**`, `sdk/src/chain.js` and
`sdk/src/tx-identity.js` (read-only leaves) may be imported; never
server/src, never the wasm module directly, never a builder / signer /
store / http / config / submit module, never a database driver (the
launcher injects `pg`). `core/`, `sdk/`, `server/`, `web/`, `mcp/` never
import the facilitator.

## Tests

```
node --test integrations/test/x402f-design-freeze.test.js \
            integrations/test/x402f-policy-claims-principals.test.js \
            integrations/test/x402f-hostile.test.js \
            integrations/test/x402f-service-integration.test.js \
            integrations/test/dependency-direction.test.js
POLICYVAULT_TEST_PG_PORT=… POLICYVAULT_TEST_PG_USER=… POLICYVAULT_TEST_PG_DATABASE=… \
  node --test integrations/test/x402f-claims-pg.test.js
```

Live testnet-10 proof: `tools/testnet-x402-facilitator-proof.js` (test
keys only; a local synced UTXO-indexed node), evidence in
`docs/testnet-x402-facilitator-evidence.json`.

## Honest ecosystem statement

No upstream Kaspa x402 scheme exists. This facilitator interoperates
only with resource servers configured for the proposed
`pv-x402-kaspa-exact-upfront/1` scheme and must not be described as
"x402-compatible" without that qualification (adapter spec §6.5 stays
OPEN). Residual risks are stated, not hidden: a reorg after
CHAIN_VERIFIED (bounded by the depth policy; the depth is in the
evidence), outputs spent before `/settle` are unobservable (kaspad has no
transaction index — settle before spending), and `payTo` reuse by a
resource server is refused rather than resolved.
