# PolicyVault Public Release Manifest

Every exported path, its reason, and its category. Derived from the
mainnet-verified private release (tag `mainnet-r1`) plus the authorized
release-cleanup changes (RPC-port documentation correction,
checkout-relative data roots, header branding, public support contact).
Application source and test files are byte-identical to the verified
private tree; only presentation documents were rewritten for public
release. Source comments retain internal provenance labels (development
checkpoint letters and names of private evidence documents); these
reference the private engineering record, contain no secrets or personal
data, and are intentionally unmodified so public source stays identical
to the verified release.

| Path | Reason required | Category |
|---|---|---|
| `LICENSE` | Apache-2.0 (owner-selected 2026-08-23) | license |
| `NOTICE` | Apache-2.0 attribution notice | license |
| `README.md` | install/run/verify entry point | documentation |
| `SECURITY.md` | security model, honest verification status, reporting channel | documentation |
| `.gitignore` | protects runtime data roots, env files, keys, build artifacts | build |
| `PUBLIC_RELEASE_MANIFEST.md` | this manifest | documentation |
| `contracts/PolicyVault.v0.4.1.sil` | the deployed production covenant (consensus reference) | runtime |
| `contracts/PolicyVault.v0.4.sil` | frozen prior covenant; supported for existing vaults; regeneration target | runtime |
| `contracts/PolicyVault.v0.3.sil` | frozen prior covenant; legacy vault support | runtime |
| `contracts/PolicyVault.v0.2.sil` | frozen prior covenant; legacy vault support | runtime |
| `contracts/PolicyVault.v0.1.beta.sil` | frozen first covenant; legacy vault support (`config.contractSource`) | runtime |
| `sdk/package.json`, `sdk/package-lock.json` | dependency manifests (reproducible install) | build |
| `sdk/src/*.js` (47 files) | the SDK: config/network gates, exact-state compilers, Merkle trees, builders, freeze/sign/finalize, VM preflight, submission + chain proof, reconciliation, manifests, claims, audit, donation validation, ux normalization | runtime |
| `sdk/test/*.js` (51 files) | UNIT/PROPERTY/SDK/API/BROWSER/hostile/sabotage/crash/concurrency/approval/wallet-session/terminal/mainnet-gate suites — the released verification story | verification-test |
| `server/package.json` | server manifest | build |
| `server/src/{server,api,audit}.js` | loopback HTTP server, API, durable audit | runtime |
| `web/{index.html,app.js,app-v4.js,wallet.js,identity.js}` | browser dashboard + wallet adapters (untrusted presentation) | runtime |
| `web/favicon.png` | approved PolicyVault branding mark | asset |
| `agent-sdk/index.js` | headless delegate interface for automation | runtime |
| `tools/gen_v4_1.js`, `tools/gen_v4.js`, `tools/gen_v3.js` | deterministic covenant generators (byte-identity verification) | build / verification-test |
| `tools/h2-browser-polish-acceptance.js` | served-app acceptance suite (real server + node; no signing/broadcast) | verification-test |
| `tools/testnet-v4_1-{lifecycle,http-e2e,standardness-gate,adversarial,concurrency,crash-reconcile}.js`, `tools/testnet-v4-lifecycle.js` | live testnet-10 verification drivers (optional; local test keys; testnet only) | verification-test |
| `tests/vm/Cargo.toml`, `tests/vm/src/**`, `tests/vm/tests/*.rs` (15 suites) | real-VM covenant verification workspace (TxScriptEngine; production + adversarial + encoder-integration + SDK-integration suites). Requires sibling `~/silverscript` checkout (relative path) + public rusty-kaspa git tag | verification-test |
| `docs/covenant-spec-v0.4.1.md` | deployed protocol specification | documentation |
| `docs/covenant-spec-v0.4.md`, `docs/covenant-spec-v0.3.md`, `docs/covenant-spec-v0.2.md`, `docs/covenant-spec.md` | frozen prior protocol specifications (legacy vault support) | documentation |
| `docs/architecture.md` | system architecture | documentation |
| `docs/threat-model.md` | threat/invariant/enforcement/test matrix | documentation |
| `docs/security-invariants.md` | invariant ledger | documentation |
| `docs/fee-mass-spec.md` | exact fee/mass model | documentation |
| `docs/wallet-adapters.md` | wallet integration contract (KasWare + generic adapter) | documentation |
| `docs/test-plan.md` | layered test architecture + how to run | documentation |
| `docs/deployment.md` | environments, mainnet opt-in, deployment posture | documentation |
| `docs/operations.md` | operator runbook (health, reconcile, backup/restore) | documentation |
| `docs/product-policy.md` | permanent free-forever / no-patents / license policy | documentation |
| `docs/organization-model.md` | off-chain organization metadata model | documentation |

## Intentionally excluded

Private engineering record and runtime state, per the release directive:
Git history and `.git/`; continuation notes; owner directives and
checkpoint documents; internal review/finding/evidence archives
(`docs/v0*-*`, `docs/testnet-evidence.md`, `docs/production-release.md`,
`docs/production-completion-checklist.md`, `docs/completion-report.md`,
`docs/mainnet-r1-smoke-evidence.md`, H2 runbooks, jobvault reuse audit);
`contracts/experiments/` and the exploratory experiment test files that
depend on them; v0.1/v0.2-era testnet driver tools; runtime data roots
(`data/`, `data-mainnet/` — including all live vault/request/claim/
receipt/audit state); `keys/`, `wallets/`, `.env*`, logs, caches, and
build artifacts (`node_modules/`, `tests/vm/target/`, `tests/vm/
Cargo.lock`); scratch and temporary artifacts. Mission/engineering-rule
files (`POLICYVAULT_MISSION.md`, `POINT_NG.md`, `CLAUDE.md`,
`POLICYVAULT_CONTINUATION_NOTES.md`) remain private.

Public chain transaction ids are not secrets, but the private evidence
archives that discuss them are not needed to run, build, verify, or
understand the released application.
