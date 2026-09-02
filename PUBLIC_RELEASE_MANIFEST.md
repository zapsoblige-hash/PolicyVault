# PolicyVault Public Release Manifest — v1.5.0 (v0.5 token-controller covenant, byte-frozen; least-privilege discovery + console correctives; MCP 1.4.2; illustrated onboarding)

Every published path, why it is included, and everything intentionally
excluded. This release was assembled as a FRESH tree (no git ancestry)
from the current accepted source, exported with `git archive` (tracked
files only) plus the release documents written for publication.

## Source ↔ live-production identity (unambiguous)

| Fact | Value |
|---|---|
| Live production | https://app.policy-vault.org |
| Live image | `policyvault-app:fullscale-rc8, digest sha256:ea638865c18f5cdac7cecb61eba1ff7f252f1bff630c7455146ea5ea69847520 — DEPLOYED 2026-09-02, automated-accepted` |
| Live buildId (served by `/api/v1/health`) | `1c02162` |
| Production runtime source | `1c02162` = the v1.3.0/v1.4.0 production source `6c3177f` + ONLY the six-file corrective delta (`server/src/api.js`, `server/src/capabilities.js`, `web/app.js`, `web/app-v4.js`, `web/wallet.js`, `web/signer-kasware-adapter.js`) + three web test files; per-file content diff of the rc8 image vs the live rc7 image = 0 added / 0 removed / exactly 9 changed files + the build-id env; covenant/VM toolchain binaries byte-identical to rc7 |
| This release's private source commit | `fc4e00d` = the corrective successor source plus the v0.5 covenant/core/SDK layers, the MCP 1.4.1 packaging + 1.4.2 discovery correctives, the illustrated onboarding (presentation only), and the roadmap addendum. The v0.5 layers are SOURCE only: no v0.5 server/API/web surface exists and no v0.5 vault exists on mainnet |
| Runtime identity of the production directories | `server/` and the six corrected `web/` files are byte-identical between this tree and the rc8 image; `core/`, `sdk/`, `web/` additionally carry the v0.5 modules and the illustrated onboarding, which the rc8 image does NOT contain (they ride the next runtime successor) |
| Publication source snapshot | **668 of 678 published files are byte-identical to the private source at `fc4e00d`**; 6 are public-presentation-modified (the same carried set as every release since v1.1.0 plus the release documents; none runtime), and 4 are public-only release documents. Verified mechanically file-by-file |
| Covenant identity | `contracts/PolicyVault.v0.5.sil` sha256 `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9` — **COVENANT-BYTE-FROZEN 2026-09-02** (regenerate + verify with `OUT=<path> node tools/gen_v5.js`; pinned by `sdk/test/covenant-freeze-v5.test.js`); v0.3 / v0.4 / v0.4.1 byte-identical to their frozen identities (regenerated from this tree) |
| Android APK identities (clean-tree rebuild from THIS public tree) | debug `aed497ed1f39a78c7d7e73650b7dc9b001605543dce0ddff4c096d2a38c871c3` (4,311,250 B), unsigned release `bab83d280c675a611755f423947e8f122d6df377824b60044a75e45a16a3daa4` (3,321,201 B) — DEVELOPMENT; release posture: INTERNET + self-owned receiver permission only, `allowBackup=false`, not debuggable; no production signing key exists |
| MCP package identity | npm `policyvault-mcp@1.4.2` PUBLISHED (tarball sha256 `2f9ff1b85d9097128a7936f503d15418e5b7157e5730e599dfed2fcc9519768e`, shasum `e33bcc6549c662a0d1b098f68efb6fdd4d5d063f`), registry `io.github.zapsoblige-hash/policyvault` 1.4.2 |

The private repository's history is not published. This tree advances
the existing public repository by a normal successor commit; no prior
public history is rewritten.

## Included (678 files)

By category: build 36, documentation 68, other 7, runtime 384, verification-test 183.

Everything in the v1.4.0 inventory (see that release's manifest) plus
exactly these additions (61 files):

- `contracts/PolicyVault.v0.5.sil`
- `contracts/vendor/README.md`
- `contracts/vendor/kcc20-reference.sil`
- `core/assets/blake2b.js`
- `core/assets/descriptor.js`
- `core/assets/index.js`
- `core/assets/kcc20.js`
- `core/assets/test/blake2b.test.js`
- `core/assets/test/descriptor.test.js`
- `core/assets/test/fixtures/kcc20-template-v1.json`
- `core/assets/test/index.test.js`
- `core/assets/test/kcc20.test.js`
- `core/explain/token-explain.js`
- `core/intent/test/token-manifest-v5.test.js`
- `core/intent/token-manifest-v5.js`
- `core/model/agent-merkle-v5.js`
- `core/model/compute-budget-v5.js`
- `core/model/test/agent-merkle-v5.test.js`
- `core/model/test/compute-budget-v5.test.js`
- `core/model/test/fixtures/token-agent-leaf-v5.json`
- `core/model/test/vault-state-v5.test.js`
- `core/model/test/vault-transitions-v5.test.js`
- `core/model/token-amounts.js`
- `core/model/vault-state-v5.js`
- `core/model/vault-transitions-v5.js`
- `docs/covenant-spec-v0.5.md`
- `docs/postlaunch/roadmap-dex-adapter-and-protocol-evolution.md`
- `docs/postlaunch/v0.5-asset-descriptor-and-onboarding.md`
- `docs/postlaunch/v0.5-byte-freeze-readiness.md`
- `docs/postlaunch/v0.5-covenant-byte-freeze.md`
- `docs/postlaunch/v0.5-covenant-reread.md`
- `docs/postlaunch/v0.5-design-freeze.md`
- `docs/postlaunch/v0.5-implementation-status.md`
- `docs/postlaunch/v0.5-template-carriage-decision.md`
- `mcp/core/MANIFEST.json`
- `mcp/core/README.md`
- `mcp/core/model/canonical-json.js`
- `mcp/test/core-sync.test.js`
- `mcp/test/mcp-discovery-scopes.test.js`
- `mcp/test/package-closure.test.js`
- `mcp/test/package-consumer.test.js`
- `mcp/tools/candidate-proof.js`
- `mcp/tools/remote-proof.sh`
- `mcp/tools/sync-core.js`
- `sdk/src/agent-merkle-v5.js`
- `sdk/src/contract-compiler-v5.js`
- `sdk/src/manifest-v5.js`
- `sdk/src/token-program-kcc20.js`
- `sdk/src/vault-builders-v5.js`
- `sdk/src/vault-state-v5.js`
- `sdk/src/vault-transitions-v5.js`
- `sdk/test/covenant-freeze-v5.test.js`
- `sdk/test/manifest-v5.test.js`
- `sdk/test/token-manifest-v5.test.js`
- `sdk/tools/gen-v5-vectors.js`
- `tests/vm/tests/v5_fixture_capture.rs`
- `tests/vm/tests/v5_production.rs`
- `tests/vm/tests/v5_sdk_integration.rs`
- `tools/gen_v5.js`
- `web/onboarding.js`
- `web/test/onboarding.test.js`

Modified vs the v1.4.0 public tree (41 files):

- `conformance/agent-conformance.test.js`
- `conformance/lib/server-harness.js`
- `core/crossruntime/test/bundle-anti-drift.test.js`
- `core/model/test/purity.test.js`
- `docs/postlaunch/mcp-distribution.md`
- `docs/postlaunch/v0.5-token-d1-spike.md`
- `docs/test-plan.md`
- `mcp/README.md`
- `mcp/package.json`
- `mcp/server.js`
- `mcp/server.json`
- `mcp/src/http.js`
- `mcp/src/idempotency.js`
- `mcp/src/tools.js`
- `mcp/test/harness.js`
- `mcp/test/mcp-live-server.test.js`
- `mcp/test/mcp-protocol.test.js`
- `mobile/www/vendor-pins.json`
- `mobile/www/vendor/core-bundle.js`
- `sdk/README.md`
- `sdk/src/index.js`
- `sdk/test/http-client.test.js`
- `sdk/test/production-guard-sabotage.test.js`
- `sdk/test/sdk-entry.test.js`
- `sdk/types/index.d.ts`
- `security/hostile-ai/mcp-agent-boundary.test.js`
- `server/src/api.js`
- `server/src/capabilities.js`
- `tests/vm/Cargo.toml`
- `tests/vm/src/bin/pv_call_encoder.rs`
- `web/app-v4.js`
- `web/app.js`
- `web/core-bundle.js`
- `web/index.html`
- `web/signer-kasware-adapter.js`
- `web/test/core-bundle.test.js`
- `web/test/network-strings.test.js`
- `web/test/signer-kasware-adapter.test.js`
- `web/test/ux-responsiveness.test.js`
- `web/tools/build-core-bundle.js`
- `web/wallet.js`

## File-level classification vs the private source at `fc4e00d`

- **IDENTICAL: 668 files.**
- **PUBLIC-PRESENTATION-MODIFIED: 6 files** (none runtime): `.gitignore`, `README.md`, `SECURITY.md`, `deploy/droplet-setup.sh`, `sdk/test/covenant-generator-v3.test.js`, `sdk/test/encoder-boundvaultid.test.js`.
- **PUBLIC-ONLY: 4 files**: `CHANGELOG.md`, `LICENSE`, `NOTICE`, `PUBLIC_RELEASE_MANIFEST.md`.
- **INTENTIONALLY EXCLUDED: 130 tracked paths** (below).

## Intentionally excluded

Identical policy and set as v1.4.0 (private engineering/operational
record, directives, acceptance transcripts, `contracts/experiments/` and
their driver suites, operational data/keys/env values, internal-only
tools) plus, by the same policy, these v1.5.0 additions (10):

- `contracts/experiments/V5TokenControllerProbe.sil`
- `contracts/experiments/V5TokenControllerProbeArgTemplate.sil`
- `contracts/experiments/V5TokenControllerProbeArgTemplateLean.sil`
- `contracts/experiments/V5TokenControllerProbeTxTemplate.sil`
- `docs/postlaunch/mcp-1.4.2-candidate-proof.json`
- `docs/postlaunch/onboarding-ux-inspection.md`
- `docs/testnet-v5-evidence.json`
- `tests/vm/tests/v5_experiment_token_dual_binding.rs`
- `tests/vm/tests/v5_experiment_token_template_carriage.rs`
- `tools/testnet-v5-lifecycle.js`

No secrets, credentials, seeds, private keys, internal hostnames, or
operational identifiers are present in any published file; every tracked
file was scanned before publication and every scan hit classified
(remaining hits are the pre-classified test-fixture mock tokens, the
placeholder token in `mcp/tools/remote-proof.sh`, the intentionally public
support contact, and generic path mentions).

## Verification you can run yourself

As in v1.4.0 (suites from this tree alone, covenant regeneration ×4,
container build comparison, APK builds, `deploy/selfhost.sh`) — plus the
v0.5 layers: `cd tests/vm && cargo test` executes the v0.5 covenant on the
real engine with production bytes (`v5_production`, `v5_sdk_integration`);
`node --test core/*/test/` and `cd sdk && npm test` cover the token
parser, descriptor, model, builders, manifests and the freeze pin.
Reproduction from this public tree alone at publication: VM 252/0, SDK 891
(796 pass / 0 fail / 95 environment-skipped: PostgreSQL/live-node suites),
core 578, web 337, mcp 53, mobile 81, integrations 113, security 54,
conformance 20, python 75; npm audit 0.

## Authority statement (unchanged, load-bearing)

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

WEB/AGENT PRODUCTION: LIVE. NATIVE MOBILE: DEVELOPMENT. No external
professional security audit has occurred; nothing in this repository
claims otherwise.
