# Self-hosting PolicyVault — quickstart

Self-hosting is a first-class, **equal-security** path: the same image,
the same fail-closed configuration matrix, the same server keylessness
(no wallet secret of any role exists as a hosted secret, by design) as
the hosted deployment at app.policy-vault.org. Nothing in self-hosted
mode is a weaker-security variant.

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

## Prerequisites

- Docker with the compose plugin; Node 20+ (for the self-check and
  acceptance tools); `openssl` (secret generation).
- Sibling checkouts of the public `silverscript` and `rusty-kaspa`
  projects next to this repository (the container image vendors the
  pinned covenant/VM toolchain from them via `tools/stage-vendor.sh` —
  `up` runs it for you when `deploy/vendor/` is missing; the script
  header documents the exact expected layout, including the
  SHASUMS-verified Node dist).
- **Your own kaspad** with `--utxoindex`, synced on your chosen network
  (testnet-10 for development; your own trusted node — never a public
  one). Expose its JSON wRPC to the compose network with the private
  host-side forwarder: `node tools/staging-kaspad-proxy.js` (binds the
  Docker bridge interface only — the RPC port is never
  internet-reachable).

## One command per step

```bash
bash deploy/selfhost.sh init      # safe config generation (testnet-10 default)
bash deploy/selfhost.sh up        # build image + one-shot migration + start
bash deploy/selfhost.sh check     # health / network / posture self-check
```

The app is served on `http://127.0.0.1:3080` (loopback only). Open it,
connect a testnet wallet, and you are operating your own PolicyVault.

`init` writes `deploy/selfhost.env` (mode 600, gitignored): random
database password, your network/node settings, and the fail-closed
posture — dev/test flags are documented as *never set*, and mainnet is
impossible unless you explicitly enable it (below).

## What `check` verifies (operator verification)

- **Release identity**: served `buildId` equals your source checkout's
  commit (`git rev-parse --short HEAD`) — you know exactly what you run.
- **Network**: served network identity equals your configured network;
  node **synced** with **utxoindex** (the same node-verified identity
  the signing gate uses).
- **Posture**: readiness on postgres; dev/test flags
  (`POLICYVAULT_DEV_SIGNER`, `POLICYVAULT_LEGACY_CREATE`,
  `PV_TEST_CRASH_AT`, staging banner) absent.
- **Custody**: no wallet-secret-shaped configuration exists — custody
  stays with external signers, structurally.
- **Covenant identity**: regenerate and byte-compare yourself:
  `OUT=/tmp/pv.sil node tools/gen_v4_1.js && cmp /tmp/pv.sil contracts/PolicyVault.v0.4.1.sil`

For the full externally-driven posture suite (identity, security
headers, Origin/CSRF gate, real Schnorr auth with throwaway test keys,
tenancy isolation, body caps, cache posture, rate limiting):

```bash
bash deploy/selfhost.sh acceptance
```

## Reproducing the release you run

Every release is reproducible from this public tree alone: lockfile
installs, full suites (including the PostgreSQL and real-VM suites),
and byte-identical covenant regeneration. See
`PUBLIC_RELEASE_MANIFEST.md` for the identity chain and
`docs/test-plan.md` for the suite map.

## Day-2 operations

```bash
bash deploy/selfhost.sh backup            # pg_dump -Fc to a mode-600 file
bash deploy/selfhost.sh restore FILE      # explicit-confirmation restore
bash deploy/selfhost.sh upgrade           # after updating the source checkout
bash deploy/selfhost.sh rollback          # previous image tag (schema NOT auto-rolled-back)
bash deploy/selfhost.sh status|logs|down  # inspect / stop (data kept)
bash deploy/selfhost.sh destroy           # uninstall (explicit confirmation; deletes data)
```

Store backups encrypted and off-host. `upgrade` records the previous
image tag; `rollback` restores it but never rolls the schema back — if
you migrated, restore a backup instead (the app fails closed on a
schema newer than it expects).

## Exposing it beyond loopback (optional, explicit)

The compose file publishes the app on `127.0.0.1` only. To serve it
externally, front it with your own TLS reverse proxy or tunnel, set
`POLICYVAULT_APP_ORIGIN` to the public origin, and — only if your proxy
overwrites the client-IP header on every request — set
`POLICYVAULT_TRUSTED_PROXY_HEADER` to that header's name. Never expose
the postgres container or your kaspad RPC.

## Mainnet (real KAS — read this whole section first)

Testnet-10 is the default and the right place to learn. Mainnet
requires an explicit, deliberate init:

```bash
bash deploy/selfhost.sh init --mainnet --rpc-url ws://<your-own-mainnet-kaspad>:18110
```

- The same **dual unlock** as hosted production is written
  (`POLICYVAULT_ALLOW_MAINNET=true` + your explicit RPC URL); the
  interactive confirmation must be typed.
- Your node must be **your own trusted mainnet kaspad** with
  `--utxoindex` — never a public node.
- Mainnet **requires a TLS-capable PostgreSQL** (the app refuses
  no-TLS postgres on mainnet, by design), so the bundled TLS-less
  postgres container is not used — bring a managed or
  certificate-equipped database and fill in the generated placeholders.
- Every funds-moving signature still happens in the owner's or agent's
  own wallet over frozen, independently verified bytes — self-hosting
  changes where the coordination runs, never who holds custody.
