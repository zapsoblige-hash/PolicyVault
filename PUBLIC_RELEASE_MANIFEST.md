# PolicyVault Public Release Manifest — 1.10.10

Local fullscale-rc44 schema-011 repair candidate; deployment and publication are not inferred. Ordinary public parent: `a8f281e7e149d0b4dcb487c17caa90499612f5a6` (v1.10.8).

Image: `sha256:8208ba6fb3e01907a125881f45787fbe63df28997f977f145d1c51f06a4966a1`. Build: `df5b8de`. Runtime/export source: `df5b8deafadb2dbfb3c65f6156f57a3b52543184`.

Source checks: 66/66 selected Node-only repair checks pass with zero failures; 3 attestation-ladder suites that need PostgreSQL or an RC42 extraction are skipped by design in this Node-only run and are covered by the ladder's separately reviewed JSON and PostgreSQL runs; the 2 changed PostgreSQL-bearing suites pass 100/100 on PostgreSQL 16.4 in a separate pre-release run on the four-fix source, after which the only runtime change is the read-only attestation ladder, which adds no SQL statement and was not re-run on PostgreSQL.

Public verification: Fresh selected repair checks from the exported tree: 66/66 pass with zero failures or skipped tests; 3 attestation-ladder suites that need PostgreSQL or an RC42 extraction are skipped by design. Exact result SHA256 `ab9155b096f81ea3113812e8d33f79133f0d8ea460d5fad2bd8ae1d55229dabf`. Historical evidence applies only to explicitly unchanged bytes; this is not a fresh full SDK/PostgreSQL, VM or financial-cycle claim.

Unchanged MCP 1.6.2: `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`. Existing public presentation transforms and privacy exclusions are preserved. License and notices remain Apache-2.0, byte-identical to the published baseline and MCP package.

Files: 1159; source-identical: 1149; presentation-modified: 8; public-only documents: 2.

Presentation modifications:
- `README.md`
- `SECURITY.md`
- `deploy/droplet-setup.sh`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/deposit-terminal-with-retained-token.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/interleaved-agents.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/latest-delegate.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/replaced-agent-and-recipients.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/terminal-with-retained-token.json`
