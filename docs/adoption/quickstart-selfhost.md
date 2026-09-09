# Quickstart: self-hosting PolicyVault

**Status: IMPLEMENTED · INTEGRATION-VERIFIED, outsider clean-environment
re-tested (`tools/selfhost-acceptance.sh`, 22/22 steps PASS,
`docs/postlaunch/selfhost-flagship-retest.md`).** This page only points
at the already-proven path; it does not restate it, so it cannot drift
out of sync. The full instructions are `docs/selfhost-quickstart.md` —
read that page to actually self-host.

## The claim, and its evidence

Self-hosting is a first-class, **equal-security** path: the same
container image, the same fail-closed configuration matrix, the same
server keylessness (no wallet secret of any role exists as a hosted
secret) as the hosted deployment at app.policy-vault.org. Nothing in
self-hosted mode is a weaker-security variant.

- **Real script**: `deploy/selfhost.sh` — `init` / `up` / `check` /
  `acceptance` / `backup` / `restore` / `upgrade` / `rollback` /
  `status` / `logs` / `down` / `destroy`.
- **Real evidence**: `tools/selfhost-acceptance.sh` ran a clean-checkout,
  outsider-perspective re-test this wave and found and fixed three
  genuine first-run defects (a `pipefail` break on a missing vendor
  directory, undocumented prerequisites, and a broken `upgrade` fallback
  on git-less checkouts). The fixed re-run: **22/22 steps PASS**,
  including real Schnorr authentication (37/37 in the deeper
  `deploy/selfhost.sh acceptance` suite), backup/restore into an
  isolated database with row-count + hash verification, upgrade/rollback
  identity, log redaction, and a hidden-dependency scan.
- **Reproducibility**: every release is reproducible from the public
  tree alone — lockfile installs, full suites including PostgreSQL and
  real-VM suites, and byte-identical covenant regeneration
  (`PUBLIC_RELEASE_MANIFEST.md`).

## The three commands

```bash
bash deploy/selfhost.sh init      # safe config generation (testnet-10 default)
bash deploy/selfhost.sh up        # build image + one-shot migration + start
bash deploy/selfhost.sh check     # health / network / posture self-check
```

The app is served on `http://127.0.0.1:3080` (loopback only) until you
deliberately expose it — see `docs/selfhost-quickstart.md`'s "Exposing
it beyond loopback" section.

## Prerequisites, in one place

`docs/selfhost-quickstart.md` §"Prerequisites" is the authoritative list
(Docker + compose, Node 20+, `openssl`, a Rust toolchain, sibling
`silverscript` / `rusty-kaspa` checkouts, the pinned Node runtime
tarball, and your own `kaspad` with `--utxoindex`). Do not duplicate
that list here — it changes with the toolchain, and a second copy would
drift.

## Mainnet self-hosting

Testnet-10 is the default and the right place to learn. Mainnet
self-hosting requires the same explicit dual unlock as hosted production
(`POLICYVAULT_ALLOW_MAINNET=true` + your own trusted mainnet `kaspad`
with `--utxoindex`, never a public node) and a TLS-capable PostgreSQL —
see `docs/selfhost-quickstart.md` §"Mainnet" for the exact procedure.
Every funds-moving signature still happens in your own wallet over
frozen, independently verified bytes: self-hosting changes where the
coordination runs, never who holds custody.

## What is not yet proven

- **Wallet-auth end-to-end is NOT-TESTED-HEADLESS** — it needs a real
  browser and a real KasWare session; the request/challenge path itself
  is proven headlessly, and the full Schnorr sign-in is proven by
  `prod-acceptance.js`'s real-Schnorr-with-test-keypair flow.
- `sdk/src/chain.js`'s `connectVerified` can be slow/silent against an
  unreachable-but-routable RPC endpoint — a shared-code issue, present
  in hosted mode too, not self-host-specific.
