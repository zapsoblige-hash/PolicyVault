# PolicyVault Public Release Manifest — 1.9.3 (PRODUCTION RELEASE `fullscale-rc31`)

Every published path, why it is included, and everything intentionally excluded. This release was assembled as a FRESH tree (no private git ancestry) from the exact accepted private source commit, exported with `git archive` (tracked files only) minus the recorded exclusion set, plus the release documents written for publication. The private repository's history is not published; this tree advances the existing public repository by a normal successor commit; no prior public history is rewritten.

## Source ↔ live-production identity (unambiguous)

| Fact | Value |
|---|---|
| Live production | https://app.policy-vault.org — the served `/api/v1/health` buildId is authoritative for what is live at any moment (`ec80d60` = this release; `9dbc5f7` = the preceding rc30 build) |
| Live image after this release's rollout | `policyvault-app:fullscale-rc31` — image `sha256:cae6b7e7cb073a17b7f9dc0dd54288556e13c6157f08a1712e91624e0878fc32` — buildId `ec80d60` (the private release records state whether and when the rollout happened; the served buildId is authoritative) |
| This release's private source commit (build source = runtime + tests + harness) | `ec80d60` (lane `flagship-ux-successor`); the published tree is exported from the final docs commit `281984c5f62c789e446df8571bce11dd0803907a` (runtime bytes identical to the build source — verified mechanically, `git diff` over every runtime path is empty, and by the final-tree image rebuild recorded in the private release record) |
| `git archive 281984c5f62c789e446df8571bce11dd0803907a` sha256 | `463dfc97b417facc14ce4372ac8c6c78896f25a2cb7b70bf477574566768a38f` |
| Covenant identity (frozen) | `v0.3` `073d3243…` · `v0.4` `8f87deab…` · `v0.4.1` `421bfed8…` · `v0.5` `c693aeff…` · `v0.6` `c7c5f22c…` · `v0.7-root` `69417514…` · `v0.7-payment` `09cdbb6c…` (full hashes pinned by `sdk/test/covenant-freeze-v*.test.js`); `v0.7-kas` and `v0.7-payment-hd` are unfrozen candidates |
| MCP package identity | npm `policyvault-mcp@1.5.0` PUBLISHED 2026-09-09 (source in `mcp/`, unchanged by this release; registry tarball sha256 `73567fe0858b8a1c2382adb28dbc8b5381f56015b2a43532b7acf637e4dfc5b9`, byte-identical to the audited artifact; no republish) |
| Release signing | `release-signers.json` carries ONE signer entry (placeholder public key `OWNER-TO-FILL`, threshold 1); no release has been signed; one real signer is the truthful current policy |
| License | Apache-2.0 (`LICENSE`, `NOTICE`, package metadata); third-party MIT notices remain intact and do not relicense PolicyVault |

## Classification of every published path (1104 files)

| classification | count |
|---|---|
| PUBLISHED from the private source (byte-identical to the source commit) | 1094 |
| PUBLIC-ONLY release documents (written for publication) | 2 (CHANGELOG.md, PUBLIC_RELEASE_MANIFEST.md; LICENSE and NOTICE are byte-identical to the source commit and counted above) |
| PUBLIC-PRESENTATION-MODIFIED (byte-different from the source commit) | 8 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-prev-release-exclusion-set | 147 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-probe-experiments | 7 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-task-dirs | 2407 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-internal-program-planning-records | 1 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-candidate-decision-promotion-packets | 40 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-private-acceptance-correction-erratum-records | 3 |
| INTENTIONALLY-EXCLUDED — EXCLUDED-upstream-prepared-not-posted | 2 |

Modified paths (compared after all presentation edits):

- `README.md`
- `SECURITY.md`
- `deploy/droplet-setup.sh`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/deposit-terminal-with-retained-token.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/interleaved-agents.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/latest-delegate.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/replaced-agent-and-recipients.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/terminal-with-retained-token.json`

### Added since the published v1.9.2 tree (3 files)

- `tools/protected-pg-backup.py`
- `tools/test_protected_pg_backup.py`
- `web/test/org-root-mainnet-availability.test.js`

### Byte-different from the published v1.9.2 tree (10 files; the release documents CHANGELOG.md, README.md, SECURITY.md are regenerated every release)

- `CHANGELOG.md`
- `PUBLIC_RELEASE_MANIFEST.md`
- `README.md`
- `SECURITY.md`
- `tools/image-privacy-classifications.json`
- `web/app-v4.js`
- `web/org-root-ui.js`
- `web/refusal-explain.js`
- `web/test/network-strings.test.js`
- `web/test/refusal-explain.test.js`

### Removed since the published v1.9.2 tree (0 files)


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

### EXCLUDED-task-dirs (2407)

2407 paths under: docs/postlaunch/audit-evidence/rc12-internal-review, docs/postlaunch/audit-evidence/rc12-internal-review/logs, docs/postlaunch/audit-evidence/rc12-internal-review/probes, docs/postlaunch/audit-evidence/rc13-internal-review, docs/postlaunch/audit-evidence/rc13-internal-review/logs, docs/postlaunch/audit-evidence/rc13-internal-review/probes, docs/postlaunch/audit-evidence/rc14-internal-review, docs/postlaunch/audit-evidence/rc14-internal-review/logs, docs/postlaunch/audit-evidence/rc14-internal-review/probes, docs/postlaunch/audit-evidence/rc15-internal-review, docs/postlaunch/audit-evidence/rc15-internal-review/logs, docs/postlaunch/audit-evidence/rc15-internal-review/probes, docs/postlaunch/audit-evidence/rc16-internal-review, docs/postlaunch/audit-evidence/rc16-internal-review/logs, docs/postlaunch/audit-evidence/rc16-internal-review/probes, docs/postlaunch/audit-evidence/rc16-internal-review/redfirst/rc15, docs/postlaunch/audit-evidence/rc16-internal-review/redfirst/rc16, docs/postlaunch/audit-evidence/rc18-internal-review, docs/postlaunch/audit-evidence/rc18-internal-review/probes, docs/postlaunch/audit-evidence/rc19-internal-review, docs/postlaunch/audit-evidence/rc19-internal-review/logs, docs/postlaunch/audit-evidence/rc19-internal-review/probes, docs/postlaunch/audit-evidence/rc20-internal-review, docs/postlaunch/audit-evidence/rc20-internal-review/probes, docs/postlaunch/audit-evidence/rc21-internal-review, docs/postlaunch/audit-evidence/rc21-internal-review/probes, docs/postlaunch/audit-evidence/rc26-internal-review, docs/postlaunch/audit-evidence/rc26-internal-review/logs, docs/postlaunch/audit-evidence/rc26-internal-review/logs/image, docs/postlaunch/audit-evidence/rc26-internal-review/probes, docs/postlaunch/ux-evidence/0bfb40b, docs/postlaunch/ux-evidence/0bfb40b/after, docs/postlaunch/ux-evidence/0bfb40b/lane, docs/postlaunch/ux-evidence/13a5306, docs/postlaunch/ux-evidence/13a5306/after, docs/postlaunch/ux-evidence/13a5306/lane, docs/postlaunch/ux-evidence/208767f, docs/postlaunch/ux-evidence/208767f/lane, docs/postlaunch/ux-evidence/23551d2, docs/postlaunch/ux-evidence/23551d2/after

### EXCLUDED-internal-program-planning-records (1)

- `docs/postlaunch/flagship-ux-field-map.md`

### EXCLUDED-candidate-decision-promotion-packets (40)

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
- `docs/postlaunch/fullscale-rc29-codex-launch-review.md`
- `docs/postlaunch/fullscale-rc29-deployment-runbook.md`
- `docs/postlaunch/fullscale-rc29-remediation-closure.md`
- `docs/postlaunch/fullscale-rc30-backup-closure.md`
- `docs/postlaunch/fullscale-rc30-backup-permissions-handoff.md`
- `docs/postlaunch/fullscale-rc30-codex-reverification-handoff.md`
- `docs/postlaunch/fullscale-rc30-codex-reverification.md`
- `docs/postlaunch/fullscale-rc30-deployment-runbook.md`
- `docs/postlaunch/fullscale-rc30-mainnet-human-acceptance.md`
- `docs/postlaunch/fullscale-rc30-provider-evidence-and-cache-verification.md`
- `docs/postlaunch/fullscale-rc30-release-remediation.md`
- `docs/postlaunch/fullscale-rc31-codex-reverification-handoff.md`
- `docs/postlaunch/fullscale-rc31-deployment-runbook.md`
- `docs/postlaunch/fullscale-rc31-release.md`
- `docs/postlaunch/public-v1.7.0-candidate-packet.md`
- `docs/postlaunch/public-v1.8.0-candidate-packet.md`
- `docs/postlaunch/rc8-f03-edge-mitigation-packet.md`
- `docs/postlaunch/wave2-human-testnet-acceptance-runbook.md`
- `docs/postlaunch/wave2-promotion-packet.md`
- `docs/postlaunch/wave2-rc11-deployment-template.md`

### EXCLUDED-private-acceptance-correction-erratum-records (3)

- `docs/postlaunch/rc30-org-availability-correction.md`
- `docs/postlaunch/rc30-owner-workflow.md`
- `docs/postlaunch/v1.9.2-public-erratum-draft.md`

### EXCLUDED-upstream-prepared-not-posted (2)

- `docs/upstream/kip9-covenant-storage-mass-plurality-writeup.md`
- `docs/upstream/kip9-plurality-repro.js`

No keys, wallets, env files, tunnel credentials, tokens, cloud credentials, internal hostnames, internal IP addresses, droplet identifiers, or private filesystem paths are published. The Publication Safety Addendum audit (history + tree + image layers) and its classified results are recorded in the release packet; `PUBLICATION_PRIVACY_PASS` is recorded there only after every finding was resolved.

