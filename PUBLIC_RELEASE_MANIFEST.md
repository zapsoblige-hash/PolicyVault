# PolicyVault Public Release Manifest — 1.10.6 (fullscale-rc40 candidate)

This local candidate uses a fresh export without private ancestry. It is staged for independent review; this document does not assert deployment, package publication or human acceptance. Public history will advance from v1.9.3 by one ordinary successor commit.

| Identity | Exact value |
|---|---|
| Image | `policyvault-app:fullscale-rc40` / `sha256:3919653b7316228d29c0196d329c3ee3550d07dad7ac9015ada6b98f1cc85a7c` |
| Build ID / source | `79dec5f` / `79dec5f2388e7cd4e8de7f2eb6f6a76ee1f86066` |
| Export source | `4f9307d7964af8b2e54a4e8182fd67bb2ab4a655` (runtime equality with build source checked) |
| Proposed MCP package | `policyvault-mcp@1.6.2`, SHA-256 `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`; packed files matched to export source |
| KAS covenant label | CANDIDATE; no freeze attestation or mainnet exercise inferred |
| Focused source verification | Focused RC40 source checks 94/94; new foreign-completion and existing transition recovery coverage, no failures/skips. RC38 full and RC39 affected results remain historical evidence |
| Public affected verification and original baseline | RC40 fresh public affected verification: sdk-affected 136/136, mcp 58/58; no failures or skips. The retained RC38 public baseline has 4262 JavaScript, 92 reference Python, 23 tools Python and 450 VM passes, 8 byte-identical regenerations and 3 consistency checks, with original run03/04 provenance. The separately validated RC39 affected run has 135 SDK and 58 MCP passes. Complete published path/blob/mode correspondence binds RC39 to that baseline and RC40 to exactly two recovery runtime changes, one new synthetic test, the independently reviewed section 3e freeze record, and the exact root-reviewed public classification record delta. Prior RC39 scanner-policy approval does not establish a public-byte PASS for that new record; fresh RC40 privacy is required. Historical and fresh counts overlap and are not added. This is not a full RC40 rerun. |

Every tracked source path is classified by the established export exclusions: private notes, directives, operational records, evidence, populated environments, vendor artifacts and task/key/data directories are excluded. Exact test fixtures required by published tests remain, with only their generator temporary paths redacted. LICENSE and NOTICE match the published baseline and MCP copies. The complete machine classification and privacy review are retained with the private release evidence.

Source-identical files: 1139. Public presentation changes: 8. Public-only release documents:2. Total: 1149.

Presentation changes:
- `README.md`
- `SECURITY.md`
- `deploy/droplet-setup.sh`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/deposit-terminal-with-retained-token.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/interleaved-agents.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/latest-delegate.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/replaced-agent-and-recipients.json`
- `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/terminal-with-retained-token.json`
