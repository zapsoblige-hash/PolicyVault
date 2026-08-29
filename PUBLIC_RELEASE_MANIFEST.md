# PolicyVault Public Release Manifest — v1.1.1 (Truthful, fail-closed network-identity banner)

Every published path, why it is included, and everything intentionally
excluded. This release was assembled as a FRESH tree (no git ancestry)
from the exact accepted production source, exported with
`git archive` (tracked files only) plus the release documents written
for publication.

## Source ↔ live-production identity (unambiguous)

| Fact | Value |
|---|---|
| Live production | https://app.policy-vault.org |
| Live image | `policyvault-app:fullscale-rc5`, digest `sha256:2504444b7d06a06ac152e4698cd6d4627c0392d3c44479ecfc41c5d60ff77be2` |
| Live buildId (served by `/api/v1/health`) | `b33bf4e` |
| Private source commit the image was built from | `b33bf4e` (private repository; history not published — see below). `b33bf4e` = the accepted `3a70563` production source (v1.1.0) + the network-identity-banner web fix ONLY (`web/index.html`, `web/app.js`, two web test files — one new) — see CHANGELOG v1.1.1. The per-file SHA256 manifest of the v1.1.0 and v1.1.1 container filesystems (11,051 vs 11,052 regular files) differs in exactly those four `web/` files plus the build identity |
| Publication source snapshot | **every runtime directory the container copies (`core/ sdk/ server/ web/ contracts/`) is byte-identical between `b33bf4e` and this tree**; verified mechanically against the private source: 536 files byte-identical, 6 public-presentation-modified files documented below — none of them runtime — and 4 public-only release documents. (The 10 VM test-portability files that were presentation-modified in v1.0.0 are now byte-identical: the private source carries the same portability fix.) |
| Therefore | the runtime source in this repository is byte-for-byte the source of the live production image; the container copies `core/ sdk/ server/ web/ contracts/` plus vendored toolchain binaries per `deploy/Dockerfile` |
| Covenant identity | `contracts/PolicyVault.v0.4.1.sil` (and priors) — byte-identical to the v0.4.1 public release; regenerate + verify with `tools/gen_v4_1.js` |

The private repository's history is not published (development record,
operational evidence, private directives). This tree starts a fresh
public history that ADVANCES the existing public repository (v0.4.1)
by a normal successor commit; no prior public history is rewritten.

## Included (546 files)

| Path | Files | Reason | Category |
|---|---|---|---|
| `LICENSE`, `NOTICE` | 2 | Apache-2.0 (owner-selected) | license |
| `README.md`, `SECURITY.md`, `CHANGELOG.md`, `PUBLIC_RELEASE_MANIFEST.md`, `.gitignore` | 5 | release documentation + hygiene | documentation |
| `contracts/*.sil` | 5 | the covenant sources v0.1…v0.4.1 (consensus reference; deterministic regeneration targets) | runtime |
| `core/**` | 99 | portable deterministic core: model, intent manifests + verification, explanations, governance, risk, signer protocol, cross-runtime equivalence — with its test suites | runtime + verification-test |
| `sdk/**` | 166 | Node SDK (builders, freeze/sign/finalize, VM preflight, submission/chain-proof, reconciliation, JSON+PG stores, config gates) + the full SDK test suites incl. the rc-lc1/rc-ux1/rc-gv1 regression+sabotage suites, PG-parity suites, and the external-approver discovery regression suites (`test/external-approver-discovery*.test.js`). PUBLIC-PRESENTATION-MODIFIED (2 test files, portability-only): `test/covenant-generator-v3.test.js` and `test/encoder-boundvaultid.test.js` resolve the repo root checkout-relatively instead of assuming `~/policyvault`, so the suite passes from any clone location; assertions unchanged | runtime + verification-test |
| `server/**` | 39 | hosted runtime: API, auth/tenancy/request protection, governance + risk enforcement, intent records, audit chain, webhooks, notifications, idempotency, machine identity, simulate, metrics; `migrations/001…009` | runtime |
| `web/**` | 31 | browser client, **browser-local independent verification** (`verify-intent.js`, `core-bundle.js` + anti-drift tool), USI KasWare adapter, browser test suites incl. the external-approver inbox and network-identity-banner suites | runtime + verification-test |
| `mcp/**` | 13 | MCP server + protocol/hostile suites | runtime + verification-test |
| `integrations/**` | 34 | x402 + AP2 adapters, normalization, SD-JWT, server-integration suites | runtime + verification-test |
| `conformance/**` | 12 | five-path conformance matrix (JS/Python/MCP/x402/AP2; cross-path byte equivalence) | verification-test |
| `security/**` | 5 | internal hostile-AI adversarial suites (agent-boundary pinning) | verification-test |
| `mobile/**` | 25 | native mobile scaffold — DEVELOPMENT status (README labeling; `docs/postlaunch/mobile-*`) | development |
| `python/**` | 17 | stdlib Python client + parity/live-server tests | runtime + verification-test |
| `tests/vm/**` | 23 | real Kaspa VM covenant workspace (Rust; production + adversarial + encoder/SDK-integration suites). Requires sibling public `silverscript` + `rusty-kaspa` checkouts. `src/lib.rs` and the test files resolve the repo root workspace-relatively (`CARGO_MANIFEST_DIR`), so `cargo test` passes from any clone location; as of v1.1.0 these files are byte-identical to the private source (the same portability fix now lives on both sides). The 10 `*_experiment_*`/lineage test files are NOT published — they drive design-probe contracts under `contracts/experiments/`, which is intentionally excluded (see below) | verification-test |
| `tools/` (18) | 18 | covenant generators (byte-identity), vendor staging, image privacy scan, served-app + staging acceptance drivers, the network-aware production acceptance driver (`prod-acceptance.js`), kaspad forwarder (testnet), backup/restore + header probes, testnet-10 v4/v4.1 live drivers | build + verification-test |
| `deploy/` (7) | 7 | `Dockerfile`, staging + production compose examples, env TEMPLATES (no real values), cloudflared config template, droplet first-boot script (PUBLIC-PRESENTATION-MODIFIED: the operator SSH public key is no longer baked as a default — you must supply your own; stale internal ship-step notes genericized) | build |
| `docs/` top (21) | 21 | protocol specs v0.2…v0.4.1, architecture, threat model, security invariants, fee/mass spec, wallet adapters, test plan, deployment, operations, organization model, product policy, hosted architecture/persistence/request-protection/threat-model/backup-restore/deployment | documentation |
| `docs/postlaunch/` (24) | 24 | per-surface specifications (intent manifests, browser verification, governance, risk, signer interface + KasWare mapping + CLI reference, MCP, platform agent API, python client, x402, AP2, webhooks/events, notifications, audit chain + correlation, budget reservations, conformance suite, cross-runtime equivalence, agent suspend, observability, mobile architecture + scaffold) + the internal `hostile-ai-review.md` (published as security transparency) | documentation |

## Intentionally excluded

Private engineering/operational record and secret-adjacent material —
never published:

- Git history and `.git/` of the private repository.
- Continuation notes, owner directives, mission/private operating
  documents (`POLICYVAULT_CONTINUATION_NOTES.md`, `CLAUDE.md`,
  `POLICYVAULT_MISSION.md`, `POINT_NG.md`, completion-standard
  directives).
- Internal decision/acceptance packets, including this release's
  docs-discovery successor packet (deployment/acceptance evidence and
  operational procedure — operational record, not source).
- Internal checkpoint/evidence archives: testnet/mainnet acceptance
  evidence and plans, phase evidence, execution logs, production
  runbook + promotion packet, candidate records, remediation report +
  RED-evidence captures, review/finding ledgers, gap analyses,
  falsification reviews, core-extraction wave notes
  (`docs/*evidence*`, `docs/hosted-*evidence*`, execution log,
  `docs/postlaunch/rc-*`, `fullscale-*`, `COMPLETION_STANDARD*`,
  `promotion-readiness-packet.md`, the 2026-08-27 external-approver
  incident packet + RED-evidence capture (contain production
  operational data; the fix, its regression suites, and an honest
  public account in CHANGELOG/README are published), the internal
  publication decision packet, and similar).
- Runtime state and data roots (`data/`), keys/wallets directories,
  backups and database dumps, real `.env` files (templates only are
  published), staged vendor binaries (`deploy/vendor/` — regenerated
  locally by `tools/stage-vendor.sh`).
- Operator-specific systemd units and acceptance-environment tooling
  (`deploy/pv-kaspad-*.service`, `deploy/*rc-acceptance*`,
  `tools/rc-mainnet-acceptance-forwarder.js`) and pre-v0.4 testnet
  drivers superseded by the published v4/v4.1 set.
- All credentials/secrets categories: API tokens, SSH keys, tunnel
  credentials, cookies/sessions, webhook secrets, machine
  identities, wallet keys/seeds (none of these exist in the tracked
  tree; the exclusion is enforced by construction and verified by the
  publication secret scan).
- `contracts/experiments/` (design-probe workspace) and the 10 VM
  experiment/lineage test files that exercise those probes
  (`tests/vm/tests/*experiment*`, `v2_lineage_experiment.rs`) — the
  published VM suite is exactly the production + adversarial +
  encoder/SDK-integration set, self-contained against the published
  `contracts/*.sil`.

## Reproduction pointers

- Covenant byte-identity: `node tools/gen_v4_1.js` then diff against
  `contracts/PolicyVault.v0.4.1.sil` (see `docs/test-plan.md`).
- Full suite map + exact commands: `docs/test-plan.md`.
- Container build: `tools/stage-vendor.sh && docker build -f
  deploy/Dockerfile …` (Node runtime tarball is SHASUMS-verified in
  the build; vendor binaries come from your own sibling toolchain
  builds — the image does not download code at runtime).
