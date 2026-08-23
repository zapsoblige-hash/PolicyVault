# PolicyVault

**Non-custodial delegated-spending vaults on Kaspa L1.**

PolicyVault lets a vault **owner** hand a spending key to an **agent** — an
employee, a service, a bot, or an AI agent — without handing over control of
the funds. The spending policy is enforced by **Kaspa L1 consensus** through
a covenant: even an agent who bypasses this entire application and talks
directly to a Kaspa node cannot exceed the owner's policy.

## What the covenant enforces

- **Owner-controlled vaults** — the owner key creates, manages, and closes
  every vault.
- **Agent/delegate spending** — up to 10 independent agents per vault, each
  with its own policy, spending real KAS within owner-defined limits.
- **Per-transaction caps** — a hard maximum per spend, per agent.
- **Periodic budgets** — a cumulative per-period budget with
  consensus-verified accounting (DAA-score based; roughly wall-clock time).
- **Recipient allowlists** — each agent can pay only owner-approved
  recipients (Merkle-authenticated per agent).
- **Optional approvals** — spends above an owner-set threshold require
  M-of-N approver signatures (up to 10 approvers), enforced on-chain.
- **Pause / unpause** — the owner can freeze all agent spending instantly.
- **Agent & policy management** — add, remove, rotate, and re-policy agents;
  every change is an owner-signed covenant transition.
- **Fee reserve** — a covenant-controlled reserve pays agent transaction
  fees within a per-transaction cap, so agents need no fuel wallet and the
  protected principal is never silently consumed by fees.
- **Owner recovery** — the owner can always close a vault and recover the
  entire remaining principal + reserve. No PolicyVault master key, no admin
  bypass, no custodial recovery exists.

Signing happens in your own browser wallet (**KasWare**); keys never touch
the PolicyVault server.

## Trust model — read this first

- **PolicyVault does not custody user keys.** Ever. The application never
  asks for a seed phrase, private key, or recovery material.
- **PolicyVault does not require funds to be sent to any
  PolicyVault-controlled wallet.** Vault funds sit in a covenant that only
  your keys control.
- **PolicyVault is free to use.** There are no subscription fees, no
  transaction fees, no paid tiers, and no artificial limits. Donations are
  voluntary (see the in-app Support page).
- Kaspa consensus is the security boundary. The backend, frontend, SDK, and
  API are conveniences — every covenant-enforced rule holds against a
  malicious actor with a legitimate agent key submitting transactions
  directly to a node.

## Security status

> PolicyVault has undergone extensive internal adversarial testing,
> production VM testing, real-wallet testnet testing, and a limited
> real-value mainnet smoke test. It has **not yet undergone an independent
> professional security audit**. Users should begin with conservative
> values.

See [SECURITY.md](SECURITY.md) for the full security posture and reporting
channel.

## Deployment model

This release is a **local / self-hosted, single-operator, loopback web
application**: the server binds `127.0.0.1` only and serves the browser UI
and API from one origin. It is not a hosted multi-user service — do not
expose `127.0.0.1:3080` to the public internet.

## Prerequisites

| Requirement | Notes |
|---|---|
| Node.js 20+ | application runtime (no build step) |
| rusty-kaspa checkout at `~/rusty-kaspa` | tag `v2.0.1`+, with the WASM SDK built (`wasm/nodejs/kaspa`) |
| SilverScript checkout at `~/silverscript` | with `silverc` built (`target/debug/silverc`) — compiles covenant state |
| `kaspad` node | v2.0.1+, fully synced, **with `--utxoindex`** |
| KasWare | browser wallet extension for signing |
| Rust toolchain (optional) | only for running the consensus VM test suite |

PolicyVault compiles exact covenant state locally and executes real VM
preflights, which is why the two sibling checkouts are required. Their
paths default to `$HOME/rusty-kaspa` and `$HOME/silverscript`.

## Running — testnet-10 (recommended first)

```bash
# 1. a synced testnet-10 node with the UTXO index
~/rusty-kaspa/target/release/kaspad --testnet --netsuffix=10 --utxoindex
#    JSON wRPC listens on 127.0.0.1:18210 by default

# 2. install SDK dependencies (once)
cd sdk && npm ci && cd ..

# 3. start PolicyVault (testnet-10 is the default network)
node server/src/server.js

# 4. open the dashboard
#    http://127.0.0.1:3080/
#    connect KasWare (switched to testnet-10) and create a vault
```

## Running — mainnet

Mainnet requires a deliberate multi-flag opt-in. **All three are
mandatory** — do not weaken this gate:

```bash
# a synced MAINNET node with the UTXO index
~/rusty-kaspa/target/release/kaspad --utxoindex
#    JSON wRPC listens on 127.0.0.1:18110 by default (Borsh on 17110;
#    PolicyVault speaks JSON wRPC)

KASPA_NETWORK_ID=mainnet \
POLICYVAULT_ALLOW_MAINNET=true \
KASPA_RPC_URL=ws://127.0.0.1:18110 \
node server/src/server.js
```

Mainnet state lives in its own `data-mainnet/` root (network-stamped;
never shared with testnet). The server refuses to start on mainnet with any
development/test hook enabled, refuses unsynced or index-less nodes, and
prints its full posture at startup. Start with tiny values and ramp up
gradually.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `KASPA_NETWORK_ID` | `testnet-10` | `testnet-10` or `mainnet` |
| `KASPA_RPC_URL` | `ws://127.0.0.1:18210` (testnet) | JSON-wRPC node endpoint; **required explicitly on mainnet** |
| `POLICYVAULT_ALLOW_MAINNET` | unset | must be `true` for mainnet |
| `POLICYVAULT_API_PORT` | `3080` | loopback HTTP port |
| `POLICYVAULT_DONATION_ADDRESS` | project default | mainnet donation address served on the Support page |

## Tests

```bash
# SDK / API / browser-layer suites (unit, property, hostile, sabotage,
# crash, concurrency, approval-flow, wallet-session, terminal-vault,
# mainnet network gates — all offline, no broadcasts):
cd sdk && npm test

# Consensus VM suite (real TxScriptEngine execution of the production
# covenants, adversarial matrices, production-byte encoder integration;
# requires the Rust toolchain + the sibling checkouts):
cd tests/vm && cargo test

# Served-app acceptance (real server + real synced testnet-10 node;
# creates nothing on chain, signs nothing, broadcasts nothing):
node tools/h2-browser-polish-acceptance.js

# Covenant regeneration (byte-identity check of the frozen contracts):
OUT=/tmp/regen-v4.sil node tools/gen_v4.js  && diff /tmp/regen-v4.sil  contracts/PolicyVault.v0.4.sil
OUT=/tmp/regen-v41.sil node tools/gen_v4_1.js && diff /tmp/regen-v41.sil contracts/PolicyVault.v0.4.1.sil
```

Optional live-testnet verification drivers (they broadcast on testnet-10
with test keys): `tools/testnet-v4_1-lifecycle.js`,
`tools/testnet-v4_1-http-e2e.js`, `tools/testnet-v4_1-adversarial.js`,
`tools/testnet-v4_1-concurrency.js`, `tools/testnet-v4_1-crash-reconcile.js`,
`tools/testnet-v4_1-standardness-gate.js`.

## Protocol versions

The current protocol is **v0.4.1** (`contracts/PolicyVault.v0.4.1.sil`,
spec in `docs/covenant-spec-v0.4.1.md`). Earlier covenant generations
(v0.1-beta, v0.2, v0.3, v0.4) are frozen, remain fully supported for
existing vaults, and their sources + specs ship here as consensus
references. New vaults always use the current protocol.

Frozen production covenant SHA-256:

```
v0.4    8f87deabc19aa03d9c2499c884cdb107aed6541286a460b233b111a694b81ae3
v0.4.1  421bfed824cf66a9e989f90c5b86fc7359faa070a5d94aace3c325f35ad1da4e
```

Both regenerate byte-identically from `tools/gen_v4.js` /
`tools/gen_v4_1.js`.

## Repository layout

```
contracts/   frozen covenant sources (SilverScript)
sdk/         SDK: exact state compilation, builders, freeze/sign/finalize,
             VM preflight, submission, chain proof, reconciliation + tests
server/      loopback API + static server (not a security boundary)
web/         browser dashboard (KasWare signing; untrusted presentation)
agent-sdk/   headless delegate interface for automation
tools/       covenant generators + verification drivers
tests/vm/    consensus VM test workspace (Rust; real TxScriptEngine)
docs/        protocol specs, architecture, threat model, operations
```

## License

Apache License 2.0 — see [LICENSE](LICENSE). Free for commercial use.
PolicyVault will not seek patents over its protocol or use patents to
restrict implementations (see `docs/product-policy.md`), and the Apache-2.0
patent grant makes that commitment binding for this code.

## Support

- In-app **Support** page: voluntary KAS donations + contact email.
- Contact / security reports: **zapsoblige@gmail.com** (never include seed
  phrases, private keys, or recovery material in any message).
