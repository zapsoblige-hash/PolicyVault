# PolicyVault Public Release Manifest — 1.9.1 (PRODUCTION RELEASE `fullscale-rc29`)

Every published path, why it is included, and everything intentionally excluded. This release was assembled as a FRESH tree (no private git ancestry) from the exact accepted private source commit, exported with `git archive` (tracked files only) minus the recorded exclusion set, plus the release documents written for publication. The private repository's history is not published; this tree advances the existing public repository by a normal successor commit; no prior public history is rewritten.

## Source ↔ live-production identity (unambiguous)

| Fact | Value |
|---|---|
| Live production | https://app.policy-vault.org — the served `/api/v1/health` buildId is authoritative for what is live at any moment (`f217011` = this release; `890b42c` = the preceding rc28 build) |
| Live image after this release's rollout | `policyvault-app:fullscale-rc29` — image `sha256:ab893b13aeae661921dda11bc0782f2e0e29ead61cc232409f9532ba3cc2f847` — buildId `f217011` (the private release packet records whether and when the rollout happened; the served buildId is authoritative) |
| This release's private source commit (build source = runtime + tests + harness) | `f217011` (lane `flagship-ux-successor`); the published tree is exported from the final docs commit `eff19beb61fe189a38a578a21fb1ef5dc31b0b53` (runtime bytes identical to the build source — verified by the final-tree image rebuild recorded in the packet) |
| `git archive eff19beb61fe189a38a578a21fb1ef5dc31b0b53` sha256 | `df432f14f022ba2a987c21369b35abc9113058f5d6a8c9229e1d1c581b06ced7` |
| Covenant identity (frozen) | `v0.3` `073d3243…` · `v0.4` `8f87deab…` · `v0.4.1` `421bfed8…` · `v0.5` `c693aeff…` · `v0.6` `c7c5f22c…` · `v0.7-root` `69417514…` · `v0.7-payment` `09cdbb6c…` (full hashes pinned by `sdk/test/covenant-freeze-v*.test.js`); `v0.7-kas` and `v0.7-payment-hd` are unfrozen candidates |
| MCP package identity | npm `policyvault-mcp@1.5.0` CANDIDATE (source in `mcp/`; exact-tarball clean-consumer proof in the packet; the npm publication is credential-gated — its status is stated in the packet and README) |
| Release signing | `release-signers.json` carries ONE signer entry (placeholder public key `OWNER-TO-FILL`, threshold 1); no release has been signed; one real signer is the truthful current policy |
| License | Apache-2.0 (`LICENSE`, `NOTICE`, package metadata); third-party MIT notices remain intact and do not relicense PolicyVault |

## Classification of every published path (1099 files)

| classification | count |
|---|---|
| PUBLISHED from the private source (byte-identical to the source commit) | 1097 |
| PUBLIC-ONLY release documents (written for publication) | 2 (CHANGELOG.md, PUBLIC_RELEASE_MANIFEST.md; LICENSE and NOTICE are byte-identical to the source commit and counted above) |
| PUBLIC-PRESENTATION-MODIFIED | 9 (README.md status table; SECURITY.md v1.9.1 claims table; deploy/droplet-setup.sh published in its already-public sanitized form — operator SSH public key supplied by the self-hoster via PV_OPS_PUBKEY instead of the embedded production operator key, generic ship step; the six df68a1f-produced legacy test fixtures under docs/postlaunch/ux-evidence/{codex-rc27f/fixtures,cp13-codex/probes} that the SDK suites read — their generator temp paths (inert metadata) redacted to <generator-tmp>/…) |
| INTENTIONALLY-EXCLUDED — EXCLUDED-prev-release-exclusion-set | 147 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-probe-experiments | 7 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-task-dirs | 1915 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-internal-program-planning-records | 1 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-candidate-decision-promotion-packets | 28 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-upstream-prepared-not-posted | 2 |

### Added since the v1.9.0 candidate tree (staged 2026-09-08, never published) (17 files)

- `LICENSE`
- `NOTICE`
- `mcp/LICENSE`
- `mcp/NOTICE`
- `mcp/tools/check-license.js`
- `sdk/test/fixtures/legacy-df68a1f/delegate-dup-both-completed-rc28.json`
- `sdk/test/fixtures/legacy-df68a1f/delegate-dup-prebroadcast.json`
- `sdk/test/rc28-http-body-failure.test.js`
- `sdk/test/rc28-live-stack-recovery.test.js`
- `sdk/test/rc28-webhook-target.test.js`
- `sdk/test/rc29-webhook-dns-transport.test.js`
- `tools/artifact-privacy-scan.py`
- `tools/audit-public-candidate.sh`
- `tools/build-private-safe-vendor.sh`
- `tools/image-privacy-classifications.json`
- `tools/public-privacy-classifications.json`
- `tools/test_artifact_privacy_scan.py`

## Intentionally excluded (not published)

Rules, in the order applied: the mechanically derived v1.7.0 exclusion set (147 paths: private operational records, owner directives, continuation notes, acceptance transcripts, live-test evidence, internal packets, superseded experiment probes and their VM tests); task/key/data directories and every `docs/postlaunch/ux-evidence/**` and `docs/postlaunch/audit-evidence/**` tree (internal browser/gate/review evidence with operator paths — summarized in the packets); private notes/directives; candidate/decision/promotion/deployment/hotfix packets, runbooks and templates; internal program/planning records; live acceptance/evidence transcripts; probe covenant experiments and their VM experiment tests (the `V6PoolFixture.sil` conformance fixture stays published, and so do the two probe contracts that published tests read: `V7ReviewNoD1.sil` — the review-freeze VM test's no-D1 variant — and `HDProbe.sil` with its real-engine probe suite `tests/vm/tests/hd_experiment.rs` — both pinned by hash by the HD design-freeze SDK test; measurement artefacts, not products); the KIP-9 upstream write-up prepared but not yet posted; vendored binaries and env files.

### EXCLUDED-prev-release-exclusion-set (147)

147 paths under: .dockerignore, CLAUDE.md, POINT_NG.md, POLICYVAULT_CONTINUATION_NOTES.md, POLICYVAULT_MISSION.md, contracts/experiments, contracts/experiments/fixtures/kaspakaha, data/claims/submission, data/receipts, data/vaults/1770200baa8663e2dfdf9f69022ea7fc62a355581248e47fece5b5ca14ca4fb9, deploy, docs, docs/postlaunch, tests/vm/tests, tools

### EXCLUDED-probe-experiments (7)

- `contracts/experiments/V7EmbeddedOwnersMeasureProbe.sil`
- `contracts/experiments/V7OrgRootProbe.sil`
- `contracts/experiments/V7OrgRootProbe2.sil`
- `contracts/experiments/V7RootedTokenControllerProbe.sil`
- `contracts/experiments/V7RootedTokenControllerProbe2.sil`
- `tests/vm/tests/v7_experiment_org_root.rs`
- `tests/vm/tests/v7_experiment_org_root_p2.rs`

### EXCLUDED-task-dirs (1915)

1915 paths under: docs/postlaunch/audit-evidence/rc12-internal-review, docs/postlaunch/audit-evidence/rc12-internal-review/logs, docs/postlaunch/audit-evidence/rc12-internal-review/probes, docs/postlaunch/audit-evidence/rc13-internal-review, docs/postlaunch/audit-evidence/rc13-internal-review/logs, docs/postlaunch/audit-evidence/rc13-internal-review/probes, docs/postlaunch/audit-evidence/rc14-internal-review, docs/postlaunch/audit-evidence/rc14-internal-review/logs, docs/postlaunch/audit-evidence/rc14-internal-review/probes, docs/postlaunch/audit-evidence/rc15-internal-review, docs/postlaunch/audit-evidence/rc15-internal-review/logs, docs/postlaunch/audit-evidence/rc15-internal-review/probes, docs/postlaunch/audit-evidence/rc16-internal-review, docs/postlaunch/audit-evidence/rc16-internal-review/logs, docs/postlaunch/audit-evidence/rc16-internal-review/probes, docs/postlaunch/audit-evidence/rc16-internal-review/redfirst/rc15, docs/postlaunch/audit-evidence/rc16-internal-review/redfirst/rc16, docs/postlaunch/audit-evidence/rc18-internal-review, docs/postlaunch/audit-evidence/rc18-internal-review/probes, docs/postlaunch/audit-evidence/rc19-internal-review, docs/postlaunch/audit-evidence/rc19-internal-review/logs, docs/postlaunch/audit-evidence/rc19-internal-review/probes, docs/postlaunch/audit-evidence/rc20-internal-review, docs/postlaunch/audit-evidence/rc20-internal-review/probes, docs/postlaunch/audit-evidence/rc21-internal-review, docs/postlaunch/audit-evidence/rc21-internal-review/probes, docs/postlaunch/audit-evidence/rc26-internal-review, docs/postlaunch/audit-evidence/rc26-internal-review/logs, docs/postlaunch/audit-evidence/rc26-internal-review/logs/image, docs/postlaunch/audit-evidence/rc26-internal-review/probes, docs/postlaunch/ux-evidence/0bfb40b, docs/postlaunch/ux-evidence/0bfb40b/after, docs/postlaunch/ux-evidence/0bfb40b/lane, docs/postlaunch/ux-evidence/13a5306, docs/postlaunch/ux-evidence/13a5306/after, docs/postlaunch/ux-evidence/13a5306/lane, docs/postlaunch/ux-evidence/208767f, docs/postlaunch/ux-evidence/208767f/lane, docs/postlaunch/ux-evidence/23551d2, docs/postlaunch/ux-evidence/23551d2/after

### EXCLUDED-internal-program-planning-records (1)

- `docs/postlaunch/flagship-ux-field-map.md`

### EXCLUDED-candidate-decision-promotion-packets (28)

- `docs/postlaunch/fullscale-rc10-candidate-packet.md`
- `docs/postlaunch/fullscale-rc11-candidate-packet.md`
- `docs/postlaunch/fullscale-rc12-candidate-packet.md`
- `docs/postlaunch/fullscale-rc13-candidate-packet.md`
- `docs/postlaunch/fullscale-rc14-candidate-packet.md`
- `docs/postlaunch/fullscale-rc15-candidate-packet.md`
- `docs/postlaunch/fullscale-rc16-candidate-packet.md`
- `docs/postlaunch/fullscale-rc18-candidate-packet.md`
- `docs/postlaunch/fullscale-rc19-candidate-packet.md`
- `docs/postlaunch/fullscale-rc20-candidate-packet.md`
- `docs/postlaunch/fullscale-rc21-candidate-packet.md`
- `docs/postlaunch/fullscale-rc22-candidate-packet.md`
- `docs/postlaunch/fullscale-rc26-candidate-packet.md`
- `docs/postlaunch/fullscale-rc27-claude-final-review.md`
- `docs/postlaunch/fullscale-rc27-codex-source-handoff.md`
- `docs/postlaunch/fullscale-rc28-candidate-packet.md`
- `docs/postlaunch/fullscale-rc28-codex-live-stack-review.md`
- `docs/postlaunch/fullscale-rc28-deployment-runbook.md`
- `docs/postlaunch/fullscale-rc28-live-stack-handoff.md`
- `docs/postlaunch/fullscale-rc29-candidate-packet.md`
- `docs/postlaunch/fullscale-rc29-deployment-runbook.md`
- `docs/postlaunch/fullscale-rc29-remediation-closure.md`
- `docs/postlaunch/public-v1.7.0-candidate-packet.md`
- `docs/postlaunch/public-v1.8.0-candidate-packet.md`
- `docs/postlaunch/rc8-f03-edge-mitigation-packet.md`
- `docs/postlaunch/wave2-human-testnet-acceptance-runbook.md`
- `docs/postlaunch/wave2-promotion-packet.md`
- `docs/postlaunch/wave2-rc11-deployment-template.md`

### EXCLUDED-upstream-prepared-not-posted (2)

- `docs/upstream/kip9-covenant-storage-mass-plurality-writeup.md`
- `docs/upstream/kip9-plurality-repro.js`

No keys, wallets, env files, tunnel credentials, tokens, cloud credentials, internal hostnames, internal IP addresses, droplet identifiers, or private filesystem paths are published. The Publication Safety Addendum audit (history + tree + image layers) and its classified results are recorded in the release packet; `PUBLICATION_PRIVACY_PASS` is recorded there only after every finding was resolved.

