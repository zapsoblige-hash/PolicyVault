# PolicyVault Public Release Manifest — v1.3.0 (Bearer wallet-sessions + native mobile production transport)

Every published path, why it is included, and everything intentionally
excluded. This release was assembled as a FRESH tree (no git ancestry)
from the exact accepted production source, exported with
`git archive` (tracked files only) plus the release documents written
for publication.

## Source ↔ live-production identity (unambiguous)

| Fact | Value |
|---|---|
| Live production | https://app.policy-vault.org |
| Live image | `policyvault-app:fullscale-rc7`, digest `sha256:c583b7835c6a36081cba66804ee8ecc34e130a4a9fb520ac4e2f37f3ae6cd072` |
| Live buildId (served by `/api/v1/health`) | `6c3177f` |
| Private source commit the image was built from | `6c3177f` (private repository; history not published — see below). `6c3177f` = the accepted `5b90e74` production source (v1.2.0) + exactly the bearer/native-mobile delta: the config-gated bearer wallet-session sibling in `server/src/{config-adjacent,api,auth}` (additive, default OFF), the validated mobile Capacitor Android project + native HTTP transport, the bearer/native test suites, and the mobile design docs — 74 files (14 modified, 60 added) vs `5b90e74`; see CHANGELOG v1.3.0 |
| Bearer flag state in live production | `POLICYVAULT_AUTH_BEARER_SESSIONS` ENABLED as of this release (single env line; schema 009, webhooks, kaspad, cookie web-auth unchanged) |
| Covenant/VM identity | the covenant sources and the vendored covenant/VM toolchain binaries in the rc7 image are **byte-identical to v1.2.0's rc6 image** (verified per-binary before deployment); no consensus-visible byte changed in this release |
| Publication source snapshot | **597 of 607 published files are byte-identical to the private source at `6c3177f`**; 6 are public-presentation-modified (documented below; none of them server/web/mobile runtime), and 4 are public-only release documents (`CHANGELOG.md`, `LICENSE`, `NOTICE`, this manifest). Verified mechanically file-by-file against the private source |
| Therefore | the runtime source in this repository is byte-for-byte the source of the live production image; the container copies `core/ sdk/ server/ web/ contracts/` plus vendored toolchain binaries per `deploy/Dockerfile` |
| Covenant identity | `contracts/PolicyVault.v0.4.1.sil` (and priors) — byte-identical to the v0.4.1 public release; regenerate + verify with `tools/gen_v4_1.js` |
| Android APK identities built from this exact tree | debug `f54e1bdb55c0c6f0662222913850fcb9e38b7de7b6b798f2d146e8b3b2d309d8`, unsigned release `ba4bc2262a1540d5cc1936314417c0a8f3b357d83c8c7ff081175bc6b7e3d31a` (DEVELOPMENT builds; no production signing key exists yet) |

The private repository's history is not published (development record,
operational evidence, private directives). This tree starts a fresh
public history that ADVANCES the existing public repository by a normal
successor commit; no prior public history is rewritten.

## Included (607 files)

| Path | Files | Reason | Category |
|---|---|---|---|
| `LICENSE`, `NOTICE` | 2 | Apache-2.0 (owner-selected) | license |
| `README.md`, `SECURITY.md`, `CHANGELOG.md`, `PUBLIC_RELEASE_MANIFEST.md`, `.gitignore` | 5 | release documentation + hygiene | documentation |
| `contracts/*.sil` | 5 | the covenant sources v0.1…v0.4.1 (consensus reference; deterministic regeneration targets) | runtime |
| `core/**` | 99 | portable deterministic core: model, intent manifests + verification, explanations, governance, risk, signer protocol, cross-runtime equivalence — with its test suites | runtime + verification-test |
| `sdk/**` | 167 | Node SDK (builders, freeze/sign/finalize, VM preflight, submission/chain-proof, reconciliation, JSON+PG stores, config gates) + the full SDK test suites, now including the bearer wallet-session suite (`test/hosted-auth-bearer-sessions.test.js`). PUBLIC-PRESENTATION-MODIFIED (2 test files, portability-only, carried from v1.1.0): `test/covenant-generator-v3.test.js` and `test/encoder-boundvaultid.test.js` resolve the repo root checkout-relatively; assertions unchanged | runtime + verification-test |
| `server/**` | 39 | hosted runtime: API, auth/tenancy/request protection (now incl. the config-gated bearer wallet-session sibling), governance + risk enforcement, intent records, audit chain, webhooks, notifications, idempotency, machine identity, simulate, metrics; `migrations/001…009` | runtime |
| `web/**` | 32 | browser client, **browser-local independent verification** (`verify-intent.js`, `core-bundle.js` + anti-drift tool), USI KasWare adapter, browser test suites — byte-identical to v1.2.0 | runtime + verification-test |
| `mcp/**` | 13 | MCP server + protocol/hostile suites | runtime + verification-test |
| `integrations/**` | 34 | x402 + AP2 adapters, normalization, SD-JWT, server-integration suites | runtime + verification-test |
| `conformance/**` | 12 | five-path conformance matrix (JS/Python/MCP/x402/AP2; cross-path byte equivalence) | verification-test |
| `security/**` | 5 | internal hostile-AI adversarial suites (agent-boundary pinning) | verification-test |
| `mobile/**` | 84 | native mobile app — DEVELOPMENT status: the portable web payload, the full Capacitor Android project (`mobile/android/`: gradle build, manifest, resources — no signing keys, none exist), the native HTTP transport (`www/js/platform/native-http.js`), the bearer sign-in flow, deterministic-pin tooling, test suites, and the session-bootstrap design docs | development |
| `python/**` | 17 | stdlib Python client + parity/live-server tests | runtime + verification-test |
| `tests/vm/**` | 23 | real Kaspa VM covenant workspace (Rust; production + adversarial + encoder/SDK-integration suites). Requires sibling public `silverscript` + `rusty-kaspa` checkouts; resolves the repo root workspace-relatively so `cargo test` passes from any clone location. The `*_experiment_*`/lineage test files are NOT published — they drive design-probe contracts under `contracts/experiments/`, which is intentionally excluded | verification-test |
| `tools/` | 18 | covenant generators (byte-identity), vendor staging, image privacy scan, served-app + staging acceptance drivers, the network-aware production acceptance driver (`prod-acceptance.js`), kaspad forwarder (testnet), backup/restore + header probes, testnet-10 v4/v4.1 live drivers | build + verification-test |
| `deploy/` | 7 | `Dockerfile`, staging + production compose examples, env TEMPLATES (no real values; `prod.env.example` now documents the bearer flag), cloudflared config template, droplet first-boot script (PUBLIC-PRESENTATION-MODIFIED, carried: no operator SSH key default) | build |
| `docs/` top | 21 | protocol specs v0.2…v0.4.1, architecture, threat model, security invariants, fee/mass spec, wallet adapters, test plan, deployment, operations, organization model, product policy, hosted architecture/persistence/request-protection/threat-model/backup-restore/deployment | documentation |
| `docs/postlaunch/` | 24 | per-surface specifications (intent manifests, browser verification, governance, risk, signer interface + KasWare mapping + CLI reference, MCP, platform agent API, python client, x402, AP2, webhooks/events, notifications, audit chain + correlation, budget reservations, conformance suite, cross-runtime equivalence, agent suspend, observability, mobile architecture + scaffold) + the internal `hostile-ai-review.md` (published as security transparency) | documentation |

## File-level classification vs the private source at `6c3177f`

- **IDENTICAL: 597 files** (every runtime file — server, web, sdk, core,
  contracts, mobile, mcp, python, integrations, conformance, security,
  tests/vm, tools, deploy templates, docs).
- **PUBLIC-PRESENTATION-MODIFIED: 6 files**, all carried from earlier
  releases, none runtime: `.gitignore` (public hygiene), `README.md` +
  `SECURITY.md` (public status labels; this release's updates are in
  both trees' spirit but the public wording is release-facing),
  `deploy/droplet-setup.sh` (no baked operator SSH key), and the two
  SDK test portability files listed above.
- **PUBLIC-ONLY: 4 files**: `CHANGELOG.md`, `LICENSE`, `NOTICE`,
  `PUBLIC_RELEASE_MANIFEST.md` (this file).

## Intentionally excluded

Private engineering/operational record and secret-adjacent material —
never published (same policy as every prior release):

- Git history and `.git/` of the private repository.
- Continuation notes, owner directives, mission/private operating
  documents (`POLICYVAULT_CONTINUATION_NOTES.md`, `CLAUDE.md`,
  `POLICYVAULT_MISSION.md`, `POINT_NG.md`, completion-standard
  directives).
- Internal decision/acceptance packets, deployment/acceptance evidence
  transcripts, promotion-readiness packets, candidate records, and this
  release's phase evidence (droplet identities, operational hosts,
  acceptance transcripts).
- `contracts/experiments/` (design probes, not consensus artifacts) and
  the `tests/vm` experiment/lineage suites that drive them.
- `data/` operational stores, `keys/`, `wallets/`, every `.env*` with
  real values, tunnel credentials, database dumps, tokens.
- Internal tools that only operate the private/hosted environment.

No secrets, credentials, seeds, private keys, internal hostnames, or
operational identifiers are present in any published file; every tracked
file was scanned before publication and every scan hit classified.

## Verification you can run yourself

- Reproduce the covenant bytes: `node tools/gen_v4_1.js` (see
  `contracts/` and `docs/`); compare hashes.
- Run every suite from this tree alone (Node 20, PostgreSQL for the PG
  suites, sibling `silverscript` + `rusty-kaspa` for the VM workspace):
  SDK, core, web, mcp, mobile, integrations, security, conformance,
  python, `cargo test` in `tests/vm/`.
- Build the container from `deploy/Dockerfile` and compare the served
  application bytes with https://app.policy-vault.org.
- Build the Android APKs from `mobile/` (see
  `docs/postlaunch/mobile-architecture.md`) and compare against the
  identities above.

## Authority statement (unchanged, load-bearing)

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

Bearer sessions authenticate; they never authorize signatures. No
external professional security audit has occurred; nothing in this
repository claims otherwise.
