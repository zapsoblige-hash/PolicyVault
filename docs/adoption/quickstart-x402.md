# Quickstart: x402 integration

**Status: PRODUCTION-READY (pilot deployment packet) — NOT DEPLOYED, NO
DNS.** Everything below describes real, tested code
(`integrations/x402-facilitator/`) that exists in this repository today.
No hosted instance is running anywhere; there is no public URL to call.
This page is for developers evaluating the design ahead of a future
owner-authorized pilot — do not treat any host name in this document as
live (none is given, because none exists).

## What it is

The PolicyVault x402 facilitator is a **separately deployed, unprivileged,
READ-ONLY chain verification / settlement attestation service** for the
proposed Kaspa x402 scheme `pv-x402-kaspa-exact-upfront/1` (`exact` +
`extra.paymentFlow: "upfront"`). The payer settles **first** with an
ordinary on-chain Kaspa transaction; the facilitator checks, against a
synced UTXO-indexed node it trusts, that the exact outpoint the payer
names pays exactly the required amount to exactly the required
destination inside the requirement's window at the policy's settlement
depth.

It holds **no keys, signs nothing, broadcasts nothing, escrows nothing,
nets nothing, converts nothing, and never charges.** This is structurally
enforced (`integrations/test/dependency-direction.test.js`), not a
policy promise.

## Real evidence, today

- **D1–D6 claim ladder**, exact labels, in
  `docs/postlaunch/x402-facilitator-production-readiness.md`: DESIGN
  FROZEN → IMPLEMENTED + UNIT-TESTED + INTEGRATION-TESTED →
  ADVERSARIAL-TESTED (34 hostile cases) → **TESTNET-VERIFIED** (real KAS
  and real frozen-v0.5 token payments on testnet-10, including the
  correct refusal of a consensus-rejected over-cap agent spend) →
  conformance + docs DONE.
- **Verdict:** `X402-FACILITATOR-PRODUCTION-READY` — for a
  single-instance, owner-gated pilot deployment behind a
  TLS-terminating proxy. This is a readiness statement about the code
  and its evidence; it authorizes nothing by itself. No external
  security review has occurred.
- **Hosted production operation: NOT STARTED — owner gate.** No image,
  no droplet service, no DNS, no TLS proxy, no mainnet run.

## Endpoints (the real API shape, once a pilot exists)

| route | auth | does |
|---|---|---|
| `GET /supported` | public | the one kind this deployment verifies (network, assets, `pv-x402-settlement/1`); `signers` is `{}` |
| `GET /healthz` | public | liveness only (never touches the node) |
| `POST /verify` | resource-server credential | deterministic check; `isValid: true` if and only if CHAIN_VERIFIED; never writes state |
| `POST /settle` | resource-server credential with `settle` authority | the same check plus an atomic single-use claim + evidence; idempotent replay returns the same stored evidence |

Body for `/verify` and `/settle`:
`{ "x402Version": 2, "paymentPayload": PaymentPayload, "paymentRequirements": PaymentRequirements }`
— the closed Kaspa profile in `docs/postlaunch/x402-facilitator-spec.md`
§2. Every response carries a code from the closed set (5 RETRY · 2
PENDING · 24 REFUSE · 4 AUTH); `PAYMENT_ALREADY_CLAIMED`,
`OUTPUT_MISMATCH`, `TOKEN_TEMPLATE_MISMATCH`, and `PAYMENT_NOT_OBSERVED`
(the correct answer for a transaction consensus itself rejected) have
all been exercised live on testnet-10.

## Credentials

Resource-server credentials are facilitator-issued API keys
(`Authorization: Bearer pvx402f_…`), bound to a principal with explicit
operations (`verify`, `settle`), allowed networks, and allowed `payTo`
destinations. They are **not** PolicyVault sessions or `pvmk_` machine
credentials and grant zero PolicyVault authority. Minting (once a pilot
is deployed) is an operator CLI action:

```
PV_X402F_DATA_DIR=/var/lib/pv-x402f node integrations/x402-facilitator/bin/x402-facilitator-admin.js \
  principal create --id merchant-a --networks kaspa:testnet-10 --operations verify,settle --payto kaspatest:…
PV_X402F_DATA_DIR=/var/lib/pv-x402f node integrations/x402-facilitator/bin/x402-facilitator-admin.js \
  credential mint --principal merchant-a
```

## Network identifiers

`kaspa:mainnet` and `kaspa:testnet-10` are PolicyVault's own
**provisional** CAIP-2-syntax identifiers for Kaspa — no upstream
registration is claimed. The string is never chain evidence; the node's
real network identity is independently re-verified on every observation.

## Try it yourself, today (offline / local testnet only)

Since there is no hosted pilot, the only way to exercise this now is
locally, against your own testnet-10 node:

```
integrations/test/dependency-direction.test.js       # structural: no signer/builder/submit imports
integrations/test/x402f-hostile.test.js               # the 34-case hostile matrix
node tools/testnet-x402-facilitator-proof.js           # live testnet-10 lifecycle (requires your own synced node)
```

## What is not yet available

- **No hosted instance and no DNS.** Every host name you might imagine
  for this service does not exist.
- **One Kaspa scheme only** — `pv-x402-kaspa-exact-upfront/1`. No
  upstream Kaspa x402 scheme exists yet, so this facilitator is not
  "x402-compatible" beyond that qualification.
- **No mainnet execution** of the facilitator has occurred; the code
  path is network-agnostic and testnet-proven only.
- **Security assurance is internal** (hostile matrix, permanent
  regressions, internal review); nothing here is an audit.
