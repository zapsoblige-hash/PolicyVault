# PolicyVault Public Release Manifest — v1.4.0 (Distribution: MCP registry packaging, agent examples, one-command self-hosting)

Every published path, why it is included, and everything intentionally
excluded. This release was assembled as a FRESH tree (no git ancestry)
from the current accepted source, exported with `git archive` (tracked
files only) plus the release documents written for publication.

## Source ↔ live-production identity (unambiguous)

| Fact | Value |
|---|---|
| Live production | https://app.policy-vault.org |
| Live image | `policyvault-app:fullscale-rc7`, digest `sha256:c583b7835c6a36081cba66804ee8ecc34e130a4a9fb520ac4e2f37f3ae6cd072` — **UNCHANGED by this release** |
| Live buildId (served by `/api/v1/health`) | `6c3177f` — **UNCHANGED by this release** |
| This release's private source commit | `8d6703e` = `6c3177f` (v1.3.0 production source) + ONLY non-runtime distribution additions: MCP npm/registry metadata (`mcp/package.json` version + `mcpName`, `mcp/server.json`), the MCP distribution doc, `examples/agents/`, the self-hosting tooling (`deploy/selfhost.sh`, `deploy/docker-compose.selfhost.yml`, `docs/selfhost-quickstart.md`), the v0.5 D1 research spike doc, and `.gitignore` hygiene — 12 files (2 modified, 10 added) vs `6c3177f` |
| Runtime identity | **every directory the production container copies (`core/ sdk/ server/ web/ contracts/`) is byte-identical between this tree, `6c3177f`, and the live rc7 image** — v1.4.0 deploys nothing and changes no runtime byte |
| Publication source snapshot | **607 of 617 published files are byte-identical to the private source at `8d6703e`**; 6 are public-presentation-modified (the same six as every release since v1.1.0, documented below; none runtime), and 4 are public-only release documents (`CHANGELOG.md`, `LICENSE`, `NOTICE`, this manifest). Verified mechanically file-by-file |
| Covenant identity | `contracts/PolicyVault.v0.4.1.sil` (and priors) — byte-identical to v0.4.1; regenerate + verify with `tools/gen_v4_1.js` |
| Android APK identities | **carry unchanged from v1.3.0** (debug `f54e1bdb…`, unsigned release `ba4bc226…`): `mobile/` is byte-identical to `6c3177f` (verified mechanically), so no rebuild occurred |
| MCP package identity | npm `policyvault-mcp@1.4.0`, registry name `io.github.zapsoblige-hash/policyvault` (`mcp/server.json`); the MCP suite (33 tests) is green at this exact tree |

The private repository's history is not published. This tree advances
the existing public repository by a normal successor commit; no prior
public history is rewritten.

## Included (617 files)

Everything in the v1.3.0 inventory (see that release's manifest —
runtime, verification-test, documentation, build categories unchanged)
plus exactly these additions:

| Path | Files | Reason | Category |
|---|---|---|---|
| `mcp/server.json` | 1 | official MCP registry metadata (stdio transport, env vars with secret marking, authority statement) | distribution |
| `docs/postlaunch/mcp-distribution.md` | 1 | install/config/auth/semantics/fail-closed distribution reference | documentation |
| `examples/agents/**` | 4 | thin OpenAI-Agents-SDK / LangChain / CrewAI wiring over the MCP server; no financial logic in any adapter | example |
| `deploy/selfhost.sh`, `deploy/docker-compose.selfhost.yml` | 2 | one-command equal-security self-hosting (init/up/check/acceptance/upgrade/rollback/backup/restore) | build |
| `docs/selfhost-quickstart.md` | 1 | operator quickstart incl. verification and mainnet requirements | documentation |
| `docs/postlaunch/v0.5-token-d1-spike.md` | 1 | v0.5 token research spike with explicit evidence-class labels (nothing frozen; research transparency) | documentation |

Modified vs v1.3.0 public: `mcp/package.json` (npm-publishable +
`mcpName` + version 1.4.0), `.gitignore` (adds `__pycache__/`, `*.pyc`,
self-host backup/state entries), `README.md`/`SECURITY.md`/`CHANGELOG.md`/
this manifest (release documents).

## File-level classification vs the private source at `8d6703e`

- **IDENTICAL: 607 files.**
- **PUBLIC-PRESENTATION-MODIFIED: 6 files** (carried set, none runtime):
  `.gitignore`, `README.md`, `SECURITY.md`, `deploy/droplet-setup.sh`,
  `sdk/test/covenant-generator-v3.test.js`,
  `sdk/test/encoder-boundvaultid.test.js`.
- **PUBLIC-ONLY: 4 files**: `CHANGELOG.md`, `LICENSE`, `NOTICE`,
  `PUBLIC_RELEASE_MANIFEST.md`.

## Intentionally excluded

Identical policy and set as v1.3.0 (private engineering/operational
record, directives, acceptance transcripts, `contracts/experiments/` and
their driver suites, operational data/keys/env values, internal-only
tools). No secrets, credentials, seeds, private keys, internal
hostnames, or operational identifiers are present in any published file;
every tracked file was scanned before publication and every scan hit
classified.

## Verification you can run yourself

As in v1.3.0 (suites from this tree alone, covenant regeneration,
container build comparison, APK builds) — plus:
`bash deploy/selfhost.sh init && bash deploy/selfhost.sh up && bash
deploy/selfhost.sh check` gives you a running deployment whose release
identity, network, posture, and custody model you verify yourself.

## Authority statement (unchanged, load-bearing)

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

No external professional security audit has occurred; nothing in this
repository claims otherwise.
