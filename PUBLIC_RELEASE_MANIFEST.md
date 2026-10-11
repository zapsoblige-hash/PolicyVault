# PolicyVault Public Release Manifest — 1.10.11

Local fullscale-rc45 reconciliation and delegate period-start remediation candidate; deployment and publication are not inferred. Ordinary public parent: `787de096bbdbd6c485f012f5d1b7b5ecbcb8ea4f` (v1.10.10).

Image: `sha256:32d45a3096b29eefc0dd97f2fc1e582ee00cb32236bbd7293c6626fd8bd4652d`. Build: `1fa26b33`. Runtime/export source: `1fa26b337aaf2767c75268ff8ed7f67ee83d07a3`.

Source checks: 799/799 selected Node-only checks from 62 changed suites pass with zero failures and no skipped test in a fresh run from the candidate source. The candidate's complete SDK, API, browser and MCP suites ran on the JSON store and on PostgreSQL (318 suites in both modes, 8613 passing checks, no failing check) from an extraction verified identical to that source. The hosted build-authority suite ran only as its node-free subset, so its four cases that need a live node are not claimed by these suite runs (the changelog's live evidence states where they ran), and two other suites that need a live testnet node (a live-chain attestation vector, whose offline check passed, and an organization-root genesis recovery, none of whose cases ran) timed out without a node, so their node-dependent cases are not claimed; the second part of the hierarchical-delegation hostile suite (the testnet-only `policyvault-0.7-payment-hd` generation), which needs a Rust toolchain, ran in neither mode and is not claimed.

Public verification: Fresh selected checks from the exported tree: 799/799 pass with zero failures and no skipped test. Exact result SHA256 `a89f8ab7fbe78ed54c2bd3bf3f33b830ce737f72afc51d4f242e571df923cb1c`. Historical evidence applies only to explicitly unchanged bytes; this is not a fresh full SDK/PostgreSQL, VM or financial-cycle claim.

Unchanged MCP 1.6.2: `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`. Existing public presentation transforms and privacy exclusions are preserved. License and notices remain Apache-2.0, byte-identical to the published baseline and MCP package.

Files: 1242; source-identical: 1232; presentation-modified: 8; public-only documents: 2.

Presentation modifications:
- `README.md`
- `SECURITY.md`
- `deploy/droplet-setup.sh`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/deposit-terminal-with-retained-token.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/interleaved-agents.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/latest-delegate.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/replaced-agent-and-recipients.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/terminal-with-retained-token.json`
