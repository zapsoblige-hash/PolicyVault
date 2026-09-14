# Changelog

## v1.10.6 — fullscale-rc40 release candidate

A narrowly validated retained owner-recovery conflict now returns PROTECTED_UNRESOLVED without writing when another recorded completed owner recovery owns the exact predecessor claim and the retained request, receipt, signatures and closed manifest agree. The historical losing request, winner records, claims, reservations, receipts, manifest and audit remain unchanged; its admission guard remains active. This disposition does not establish rejection or nonacceptance, remove claims, rebuild, sign or rebroadcast. Incomplete or conflicting evidence still refuses.

This candidate supersedes the blocked, unpublished fullscale-rc36, fullscale-rc37, fullscale-rc38 and fullscale-rc39 artifacts. Public v1.9.3 remains the published baseline. Its image is `sha256:3919653b7316228d29c0196d329c3ee3550d07dad7ac9015ada6b98f1cc85a7c`, buildId `79dec5f`. Deployment, public publication and independent acceptance are pending. Served health and the package registry identify what is actually delivered.

A delayed Bearer-authentication usage update can no longer restore an ordinarily revoked machine credential. The usage writer conditionally changes only lastUsedAt on the currently matching ACTIVE credential. JSON performs the latest-record check and patch without yielding under the supported one-service-writer contract; PostgreSQL applies one conditional field UPDATE. Revoked, missing or mismatched records remain unchanged, and usage telemetry never grants another scope. Fresh restart and both database lock-order regressions cover the correction. Authentication already admitted before revocation is not retroactively cancelled; initial identity/credential creation remains a separate two-record operation.

Negative settlement now requires the original submission anchor, a complete acceptance window without a reorg or this transaction's acceptance, repeated exact funding observations, exact mempool misses, absent outputs and a stable sink. Settlement of an actual node rejection requires a durable proof bound to that request and its retained rejection. An eligible stale ordinary request with transport ambiguity can instead reach NOT_BROADCAST through a nonacceptance proof bound to the original request, transaction and saved submission anchor, without inventing a rejection. Historical unproved negative labels and known-accepted node answers cannot use that ordinary fallback. A missing current output or historical error string cannot establish nonacceptance; spent or missing inputs, incomplete metadata/history, errors and contradictions retain the claim.

Recovery observes the same durable request without rebuilding, signing or rebroadcasting it. Positive completion still requires the supported outcome evidence and preserves existing records through create-only writes and matching genesis lineage. Retained v0.4.1 transitions now recover through request-bound observation, durable completion journaling, exact output script/version checks, and protected ordinary admission. Legacy NOT_BROADCAST labels and known-node answers cannot bypass these guards. Old requests without enough original evidence remain protected. Legacy headless claims require their original definition; unsupported or unavailable history is not invented. One service writer per data root remains the supported operating contract.

Source verification: Focused RC40 source checks 94/94; new foreign-completion and existing transition recovery coverage, no failures/skips. RC38 full and RC39 affected results remain historical evidence.

Public reproduction: RC40 fresh public affected verification: sdk-affected 136/136, mcp 58/58; no failures or skips. The retained RC38 public baseline has 4262 JavaScript, 92 reference Python, 23 tools Python and 450 VM passes, 8 byte-identical regenerations and 3 consistency checks, with original run03/04 provenance. The separately validated RC39 affected run has 135 SDK and 58 MCP passes. Complete published path/blob/mode correspondence binds RC39 to that baseline and RC40 to exactly two recovery runtime changes, one new synthetic test, the independently reviewed section 3e freeze record, and the exact root-reviewed public classification record delta. Prior RC39 scanner-policy approval does not establish a public-byte PASS for that new record; fresh RC40 privacy is required. Historical and fresh counts overlap and are not added. This is not a full RC40 rerun.

The KAS covenant remains labelled CANDIDATE. Any byte-freeze attestation requires independent review of the exact replacement artifacts. MCP `policyvault-mcp@1.6.2` is a proposed package (tarball SHA-256 `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`); its delivery is pending. The adapter provides unsigned scoped operations, carries no genesis/signature/submission tool, and supports root `ownerRecover` without implying rooted-vault recovery support.


## v1.9.3 — PRODUCTION RELEASE `fullscale-rc31`: organizational-root availability and refusal presentation on mainnet (owner-observed RC30 finding RC30-HA-UX-01) — browser presentation only

**WEB/AGENT PRODUCTION: LIVE at https://app.policy-vault.org — this release's build is `fullscale-rc31` (buildId `ec80d60`, image `sha256:cae6b7e7cb073a17b7f9dc0dd54288556e13c6157f08a1712e91624e0878fc32`); the served `/api/v1/health` `buildId` is authoritative for which build is active (`ec80d60` = this release, `9dbc5f7` = the preceding rc30 build, live since 2026-09-09 06:01 UTC) · NATIVE MOBILE: DEVELOPMENT.**
This release changes three browser files and nothing else at runtime (`web/app-v4.js`, `web/org-root-ui.js`, `web/refusal-explain.js`, plus three test files): no SDK, server, covenant, compiler, authorization, signing or submission byte changed; schema 011 is unchanged (migrations byte-identical), so rc30 remains a schema-compatible image-only rollback target — with the finding below reintroduced if it is ever re-activated — and every write made under either build stays readable by the other. The mainnet-creatable generation stays `policyvault-0.4.1`; new v0.7 organizational-root / payment creation remains unauthorized on mainnet, and no UI test enables it. The finding was observed by the owner during the live mainnet acceptance of rc30 and corrected by the separate AI reviewer that runs that acceptance (internal review — not an external audit); this release re-verified the correction independently, corrected one residual its own second reviewer found, rebuilt and re-verified the exact artifact, and deployed it. Security assurance stays INTERNAL and evidence-based.

### What changed for live users (mainnet exposure)

- **Organizational-root creation is offered only where it can succeed (RC30-HA-UX-01).** The Organizations view previously offered the full "Create organizational root" wizard on mainnet even though only `policyvault-0.4.1` vaults can be created there; the build was then refused by the SDK's generation guard, the refusal appeared in the global notice behind the wizard with generic "change the values" advice, and it persisted after navigating to Create Vault. Now the console reads the server's capability discovery (`GET /api/v1/capabilities`) next to the root list and enables root setup only when discovery for the SAME network advertises both `policyvault-0.7-root` and `policyvault-0.7-payment` as creatable; missing, malformed, mismatched or incomplete discovery leaves the control disabled with an upfront explanation ("not available for creation on mainnet in this release — use Create Vault for a single-owner vault, or create a hosted organization to group vaults"). Existing on-chain roots, their history and hosted organization grouping stay readable (hosted grouping never confers covenant owner authority). Discovery is presentation: the server and SDK generation gates remain the authority and are unchanged. `web/org-root-ui.js` (`rootCreationAvailability`), `web/app-v4.js` (`rootCreationAllowed`, checked before the wizard opens and again before a build).
- **Generation refusals explain themselves.** A refusal for a covenant generation that is not owner-authorized on mainnet now says that changing the wallet address or amounts cannot enable it and points at the supported single-owner Create Vault flow; the server's exact code and message stay visible verbatim. The older `BUILD_FAILED` wrapper is recognized only when its message contains the SDK guard's exact sentence for one of seven known generations — unrelated build failures keep their existing explanation. `web/refusal-explain.js`.
- **Build errors belong to the wizard.** A server refusal during root setup renders inside the wizard (announced as an alert and focused); cancelling or leaving Organizations clears only the wizard's own notices; a newer pending or uncertain-outcome warning is always preserved — including when the refused response of an abandoned build arrives late — and a build that completes after the owner cancelled is withdrawn ("withdrawn before signing") instead of re-opening a review over whatever view is now open. `web/app-v4.js` (`noteRootWizard`, `navigateTo`, the late-outcome guards in `buildAndReviewRoot`).
- Supported v0.4.1 Create Vault, the Vaults / Activity views and tab navigation are unchanged in behaviour (navigation goes through one helper that clears only a wizard-scoped notice).

### Distribution and build integrity

- Image `policyvault-app:fullscale-rc31` = `sha256:cae6b7e7cb073a17b7f9dc0dd54288556e13c6157f08a1712e91624e0878fc32`, buildId `ec80d60`, `SOURCE_DATE_EPOCH` 1789015576, base `ubuntu:26.04@sha256:2260313b…`; context = the deterministic 317-file source bundle of `ec80d60` (content id `5396ca1a…`) + the privacy-safe vendor stage (six tracked pins, byte-identical). The image's `/app` file set differs from the live rc30 image in exactly the three runtime files and three test files above.
- **Reproducibility, stated exactly.** Two pipeline builds of the identical context produce the identical image digest and byte-identical OCI archives, both under the pipeline's Docker layer cache (the first build took its base and toolchain layers from the cache and built every application layer fresh; the second build was fully cached). No cold-cache reproduction is claimed: the cold-rebuild timestamp limitation recorded for v1.9.2 is unchanged by a web-only delta. An intermediate image of the reviewer's uncorrected commit was built and verified during this release and never deployed or published.
- Exact-artifact verification on the release archive: archive ↔ build record ↔ OCI index/manifest/config ↔ loaded image id; 314 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies present, root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and inside the image.
- Fail-closed artifact privacy scan of the exact release archive: complete, 25 designated production values, 0 findings, 28 exact classifications (the new image config's nine upstream base-image build-path history commands are byte-identical to the previously classified rc30 config; the config differs from it only in the build id and the timestamps).
- `policyvault-mcp@1.5.0` is unchanged by this release (registry version and integrity re-read; no republish). Installed SDK / mobile clients are unaffected (no client-library byte changed).

### Tests and evidence (automated / internal — never human acceptance)

- Automated gates on the build source `ec80d60` (automated / internal evidence only): full web suite **815/815** (the launch floor 796 + 19 new / changed cases); the new 13-case DOM regression **13/13** GREEN, with RED classified by the failure reached — **11 fail / 2 pass** on the live rc30 web bytes (`9dbc5f7`) and **3 fail / 10 pass** on the reviewer's uncorrected commit (the two notice-scoping assertions and the late-success case); the seven affected web suites re-run on the PRODUCT BYTES extracted from the exact image (`/app/web`, `core`, `sdk/src`, `server/src`, `contracts` from the image; test-only fixtures and dev dependencies from the source commit) **227/227**; core-bundle anti-drift IDENTICAL; portable sync identical; exact-artifact verification of the release archive (archive ↔ build record ↔ OCI index / manifest / config ↔ loaded image id; 314 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and in the image); hosted-mode boot of the exact image with its own empty PostgreSQL database and the migrations run inside the container (schema 011, health `buildId ec80d60`, readiness 200, synchronized testnet-10 node with UTXO index, capabilities, six served hashes == source, anonymous build refused 401, zero financial rows); fail-closed privacy scan of the exact release archive (complete, 25 designated production values, 0 findings, 28 exact classifications).
- Public-tree delta reproduction from ONLY this release's exported candidate tree (fake HOME, the documented sibling toolchains, lockfile `npm ci`; reproduction subject = candidate A `3ceddafb…`, whose runtime bytes are identical to the final tree — the final tree differs only in the release documents): byte delta vs the reproduced v1.9.2 tree = exactly the three changed browser files, the three changed / added tests, the two added tooling files, the classifications file and the four regenerated release documents (`delta-vs-v192.txt`); every reused suite's inputs unchanged (0 differing entries under `tests/vm` — the earlier reproduction's generated `Cargo.lock` aside — `sdk/src`, `sdk/tools`, `server`, `core`, `mobile`, `mcp`, `python`, `security`, `integrations`, `conformance`, `sdk/package{,-lock}.json`; every `contracts/*.sil` identical); private-path grep = the scanner's own regex literal only (classified since v1.9.1); `npm audit` 0; core-bundle anti-drift identical; tools **20/20**; image-scan classification **4/4**; scanner unit controls **13/13**; the new protected-backup helper's unit tests **10/10**; the FULL web suite from the public tree: run 1 **803 pass / 12 fail** — every failure `pv_call_encoder` / `pv_tx_probe not built` (the RC-UX-1 browser cases and the REAL / REAL-TAMPER pre-sign cases build real v4 requests through the VM encoder; the delta script had not built the VM binaries — the same TEST ENVIRONMENT class as the v1.9.2 run 1; retained as `web-full.log.txt`), run 2 after `cargo build --bins` from the public workspace **815/815, 0 skipped** (`web-full-run2.log.txt`). VM, covenant regeneration, core, SDK, server, mobile, mcp, python, security, integrations and conformance are reused from the v1.9.1 reproduction and the v1.9.2 delta on that mechanical evidence.
- Browser: signed headless-Chromium harness on the exact image (TEST-ONLY dev signer, testnet-10, tmpfs JSON data; every section including the rooted-vault owner operations) **212/212, 0 uncaught page errors**, served bytes captured before and after the run and stable (the harness's known console-error entries retained and classified in the private record) + the UX-11 self-test failing as intended (64/65, exit 1, only the injected page error); signed-out first-run smoke in real headless Chromium on the exact image at 1280 px and 375 px — PASS, 0 page errors / 0 console errors; the 13-case DOM regression drives the real page and scripts with a synthetic wallet and intercepted HTTP. No real-wallet or human evidence is claimed by automation.
- Live (after the rollout): the rollout of this build on the hosted deployment and its served verification (plain canonical GETs of every changed asset with body hashes compared to the release image and the edge cache status recorded; a fresh-context real-Chromium check of the affected views with a synthetic wallet provider bound to an unfunded test identity for message sign-in only; the acceptance, first-run and served-extras suites through the public route) are recorded in the private release record; the served `/api/v1/health` `buildId` is authoritative for which build is active at any moment, and a browser that still holds an older copy of a changed file keeps the previous behaviour until it revalidates.
- Reused with recorded applicability (mechanically checked: no byte under `core/`, `sdk/`, `server/`, `mobile/`, `mcp/`, `tests/`, `contracts/`, `deploy/`, `python/`, `security/`, `integrations/`, `conformance/` changed between the rc30 build source `9dbc5f7` and `ec80d60` — the whole runtime delta is the three browser files): the v1.9.2 / v1.9.1 core 1343/1343, security 54/54, integrations 188/188, conformance 21/21, mcp 58/58, mobile 98/98, python 92/92, full SDK + live PostgreSQL 1399/1399, the eight webhook / notification suites 53/53, covenant regeneration IDENTICAL ×7, VM 406/5 + delta 44/44 (not one clean run — the recorded erratum stands), the rc30 exact-image webhook regression and hosted-boot evidence for the unchanged server, the MCP 1.5.0 live consumer proofs and the 100-user capacity run.
- Independent read-only reviews (internal AI reviews, not audits): the correction was written by the separate AI reviewer that runs the owner's live acceptance, with its own read-only reviewer pass; this release's session read the whole diff independently and its second read-only reviewer found one LOW presentation-only residual (the wizard's progress notice surviving Cancel; a build succeeding after Cancel re-opening the review) — corrected in this release with RED-first regressions and re-reviewed on the exact bytes ("no concrete regression found"). The reviewer's affected live re-verification follows this release; owner mainnet human acceptance follows that.

### Not in this release / limitations

- Native mobile stays DEVELOPMENT. No real-wallet (KasWare) evidence is claimed by automation for this release (the served UI check uses a synthetic wallet provider bound to an unfunded test identity for message sign-in only); the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD / KAS candidates are testnet-only; the mainnet-creatable generation stays `policyvault-0.4.1`. Silverscript v1.0 adoption (SS-UPGRADE-01) is deliberately NOT part of this release. The permanent purge-on-deploy / content-addressed-bundle follow-up (rc29-OPS-1) remains open: the origin serves the browser files with `Cache-Control: no-cache` and the edge revalidated them on every observed request, which is not a durable invalidation guarantee for every edge or existing browser copy. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry OFF.

## v1.9.2 — PRODUCTION RELEASE `fullscale-rc30`: corrections from the independent post-launch launch review of the running rc29 deployment (webhook response-socket lifetime bound, upstream Silverscript ISC notice) + evidence errata for v1.9.1

**WEB/AGENT PRODUCTION: LIVE at https://app.policy-vault.org — this release's build is `fullscale-rc30` (buildId `9dbc5f7`, image `sha256:4a6dce6e7646e9aa460340339887e117c48185bf7ecdbcae8c5107c72da8be21`); the served `/api/v1/health` `buildId` is authoritative for which build is active (`9dbc5f7` = this release, `f217011` = the preceding rc29 build, live since 2026-09-09 01:17 UTC) · NATIVE MOBILE: DEVELOPMENT.**
The rc30 activation on the hosted deployment is recorded in the private release ledger; schema 011 is unchanged (migrations byte-identical), so rc29 remains a schema-compatible image-only rollback target — with the two defects below reintroduced if it is ever re-activated — and every write made under either build stays readable by the other. The corrections come from the independent read-only launch review of the LIVE rc29 stack by the separate AI reviewer (internal review — not an external audit), which also prepared the source correction; this release re-verified that correction independently, rebuilt and re-verified the exact artifact, and deployed it. Security assurance stays INTERNAL and evidence-based; nothing here is externally audited and no external audit is part of the process.

### What changed for live users (mainnet exposure)

- **Webhook response-socket lifetime (review finding RC29-LR-01, medium — availability only)**: the delivery worker's only per-attempt deadline was cleared as soon as the receiver's response HEADERS arrived, so a receiver that acknowledged and then stalled or trickled its body below the 8 KiB drain cap could keep that socket open indefinitely inside the shared API process while the worker moved on and opened further sockets. The absolute deadline (10 s default) now survives header acknowledgement until the response ends or the socket closes; the header outcome is unchanged (2xx delivered, non-2xx failed, 3xx never followed), the byte cap, the DNS-answer pinning and the private-address refusal are intact. `server/src/events-delivery.js`; RED-first `sdk/test/rc29-webhook-response-deadline.test.js` (real loopback sockets, nine cases: complete, success-stall, refusal-stall, redirect-stall, oversized, broken, trickle, no-headers, six concurrent acknowledged stalls — 4 pass / 5 fail on the previous module → 9/9). Production impact: zero active webhook endpoints were registered at every observation; the defect could not affect authorization, custody or funds — it bounded nothing on the receiver's side.
- **Upstream Silverscript ISC notice (LS-02 extension, low)**: the shipped `silverc` compiler and the vendored KCC20 reference program come from Silverscript revision `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`; its unchanged ISC copyright and permission notice (sha256 `feee0f42096fab1ad3cbd301091c303d0f424766fa24be3cd36718fdd2a2aaa3`) now ships at `contracts/vendor/LICENSE` and, inside the image, beside the compiler at `/home/pv/silverscript/LICENSE` (`deploy/Dockerfile`); `contracts/vendor/README.md` states the provenance. PolicyVault's Apache-2.0 `LICENSE` / `NOTICE` and every other third-party notice are unchanged. This closes the identified notice obligation; it is not an exhaustive third-party licensing opinion.

### Evidence errata for v1.9.1 (public statements corrected; the published v1.9.1 tree itself is unchanged)

- `PUBLIC_RELEASE_MANIFEST.md` of v1.9.1 stated "1097 byte-identical + 2 public-only, 9 presentation-modified". The measured, disjoint classification of the same 1,099 published files is **1089 byte-identical to the source commit + 8 presentation-modified + 2 public-only**: the five legacy test fixtures under `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/` are presentation-modified by their generator-path redaction (the cp13 delegate-recovery fixture is byte-identical), and README, SECURITY and `deploy/droplet-setup.sh` are the other three. This release's manifest is generated by a corrected writer that computes disjoint categories from the actual bytes and refuses missing or unclassified paths.
- The v1.9.1 statement "two byte-identical builds" of the rc29 image is correct but both builds used the Docker layer cache; the reproducibility statement for THIS release records cache use explicitly (below).
- The v1.9.1 public-tree VM evidence was **406 passed / 5 failed** (stale v0.7 SDK vector generators; `cargo` stopped at the failing binary) followed by a **44 passed / 0 failed** delta run of the four affected binaries with the corrected generators — retained suite inventories support 450 distinct final cases, but it was not one clean 450/0 run. The dated notes in `docs/postlaunch/v0.7-covenant-byte-freeze.md`, `v0.7-kas-profile-readiness.md` and `v0.7-security-claims.md` describe the RED period; this entry states the run shape.
- Private-record errata (restore-rehearsal attribution, whole-host journal totals, image-layer reuse coverage) were corrected in the private release records by the reviewer and are carried forward there; none of them changes a public claim.

### Distribution and build integrity

- Image `policyvault-app:fullscale-rc30` = `sha256:4a6dce6e7646e9aa460340339887e117c48185bf7ecdbcae8c5107c72da8be21`, buildId `9dbc5f7`, `SOURCE_DATE_EPOCH` 1788926971, base `ubuntu:26.04@sha256:2260313b…`; context = the deterministic 316-file source bundle of `9dbc5f7` (content id `2a869676…`) + the privacy-safe vendor stage (six tracked pins, byte-identical).
- **Reproducibility, stated exactly.** Three builds were compared. The reviewer's build (2026-09-09 04:13 UTC; base/toolchain layers from the Docker layer cache, application layers built fresh) and this release's pipeline build (05:01 UTC; every step from the layer cache) produce the **identical image digest** — identical layer blobs and config; their OCI archives differ only in the index annotation that names the tag. A **cold `--no-cache` rebuild does NOT reproduce the digest**: 8 of 25 layers differ (the apt layer, the two `/tmp` COPY layers and the Node-install layer, the `useradd` layer and the three `/home/pv` vendor layers) — in modification timestamps (cache-assisted layers keep the epoch-clamped timestamps of the 2026-09-02 build that populated the cache; cold layers carry this source's epoch) and in seven build-time-stamped files (`etc/shadow` — the `pv` account's last-change day; `var/cache/ldconfig/aux-cache`; `var/log/alternatives.log`, `var/log/apt/eipp.log.xz`, `var/log/apt/history.log`, `var/log/apt/term.log`, `var/log/dpkg.log` — dates only, same sizes); every file's size, every other file's content, the dpkg package set (90 packages, identical versions) and all 14 `/app` application layers plus the permissions layer are byte-identical. The release artifact is therefore reproducible under the pipeline's layer cache; from a cold cache the application layers reproduce and the base layers reproduce in content but not in timestamps (recorded limitation; timestamp normalization of cached base layers is a follow-up, not a defect of this release's bytes).
- Exact-artifact verification on the release archive: archive ↔ build record ↔ OCI index/manifest/config ↔ loaded image id; 313 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and inside the image. The image's `/app` file set differs from the live rc29 image in exactly `server/src/events-delivery.js`, `contracts/vendor/README.md` and the added `contracts/vendor/LICENSE`.
- Fail-closed artifact privacy scan of the exact release archive: complete, 25 designated production values loaded, 0 findings, 28 exact classifications (the reviewer's scan of its own archive of the same image: identical result).
- `policyvault-mcp@1.5.0` is unchanged by this release: published on the npm registry on 2026-09-09 (registry tarball sha256 `73567fe0858b8a1c2382adb28dbc8b5381f56015b2a43532b7acf637e4dfc5b9`, byte-identical to the audited artifact, re-verified by a fresh consumer install for this release); no republish.

### Tests and evidence (automated / internal — never human acceptance)

- Automated gates on the build source `9dbc5f7` (every result with unchanged before/after source fingerprints; automated / internal evidence only): the RC29-LR-01 real-socket regression **9/9** on the source (the reviewer's run and this release's independent run) and **9/9 inside the exact image** — on the reviewer's build and again on the release tag (same digest); the eight affected webhook / notification / DNS-transport / target suites with live PostgreSQL **53/53** (44 pre-existing + 9 new; the reviewer's 44/44 + 9/9 on the same bytes; 0 skipped); exact-artifact verification of the release archive (archive ↔ build record ↔ OCI index / manifest / config ↔ loaded image id; 313 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and in the image); hosted-mode boot of the exact image with its own empty PostgreSQL database and the migrations run inside the container (schema 011, health `buildId 9dbc5f7`, readiness 200, synchronized testnet-10 node with UTXO index, capabilities, four served hashes == source, anonymous build refused 401, zero financial rows); fail-closed privacy scan of the exact release archive (complete, 25 designated production values, 0 findings, 28 exact classifications).
- Public-tree delta reproduction from ONLY this release's exported candidate tree (fake HOME, the documented sibling toolchains, lockfile `npm ci`, live PostgreSQL; reproduction subject = candidate A `ce08024a…`, whose runtime bytes are identical to this final tree — the final tree differs only in the release documents): byte delta vs the fully reproduced v1.9.1 tree = exactly the seven changed and two added files listed in `PUBLIC_RELEASE_MANIFEST.md`; every reused suite's inputs unchanged (0 differing entries under `tests/vm`, `sdk/src`, `sdk/tools`, `core`, `web`, `mobile`, `mcp`, `python`, `security`, `integrations`, `conformance`, `sdk/package{,-lock}.json`; every `contracts/*.sil` identical); private-path grep 1 (the scanner's own regex literal, classified since v1.9.1); `npm audit` 0; core-bundle anti-drift identical; tools **20/20**; image-scan classification **4/4**; scanner unit controls **13/13**; the eight affected webhook / notification / DNS-transport / target suites **53/53 with the VM binaries built from the public workspace** (a first run without the built `pv_call_encoder` failed nine notification / webhook PostgreSQL cases on that missing prerequisite — a test-environment gap of the delta script, retained as evidence — while the nine RC29-LR-01 cases passed in both runs). VM, covenant regeneration, core, web, mobile, mcp, python, security, integrations and conformance are reused from the v1.9.1 reproduction on that mechanical evidence.
- Browser: signed-out first-run smoke in real headless Chromium on the exact image at 1280 px and 375 px — PASS, 0 page errors / 0 console errors. This release changed no `web/` byte, so the signed headless-Chromium harness (212/212, 0 uncaught page errors, UX-11 self-test failing as intended) on the byte-identical rc29 bundles is reused with recorded applicability. No real-wallet or human evidence is claimed.
- Reused with recorded applicability (mechanically checked: no byte under `core/`, `web/`, `mobile/`, `mcp/`, `tests/vm`, `contracts/*.sil`, `sdk/src`, `sdk/tools` changed between the rc29 build source `f217011` and `9dbc5f7` — the whole runtime delta is `server/src/events-delivery.js`, `contracts/vendor/LICENSE`, `contracts/vendor/README.md`, `deploy/Dockerfile` and the new test): the v1.9.1 core 1343/1343, web 798/798, security 54/54, integrations 188/188, conformance 21/21, tools 20/20, mcp 58/58, mobile 98/98, python 92/92, full SDK + live PostgreSQL 1399/1399, covenant regeneration IDENTICAL ×7, VM 406/5 + delta 44/44, the signed headless-Chromium harness 212/212 on the rc29 image (identical `web/` bytes) and the 100-user capacity run (runtime deltas outside the measured mix).
- Independent read-only review (internal AI review, not an audit): the post-launch launch review of the running rc29 deployment found RC29-LR-01 and the LS-02 extension and prepared the correction; this release's session re-verified the correction and the exact artifact independently and deployed it. The affected live re-verification by the reviewer follows this release; owner mainnet acceptance follows that.

### Not in this release / limitations

- Native mobile stays DEVELOPMENT. No real-wallet (KasWare) evidence is claimed by automation; the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD / KAS candidates are testnet-only; the mainnet-creatable generation stays `policyvault-0.4.1`. Installed SDK / mobile clients are unaffected by this release (no client byte changed). Edge caching of the unchanged browser bundles is unaffected (no `web/` byte changed); the permanent purge-on-deploy / content-addressed-bundle follow-up (rc29-OPS-1) remains open. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry OFF.

## v1.9.1 — PRODUCTION RELEASE `fullscale-rc29`: corrections from the independent post-launch live-stack review of the running rc28 deployment (webhook target policy + DNS transport, SDK transport recovery key, legacy same-effect completion ownership, image/package license + privacy-safe runtime artifacts, recovery guidance)

**WEB/AGENT PRODUCTION: LIVE at https://app.policy-vault.org — this release's build is `fullscale-rc29` (buildId `f217011`, image `sha256:ab893b13aeae661921dda11bc0782f2e0e29ead61cc232409f9532ba3cc2f847`); the served `/api/v1/health` `buildId` is authoritative for which build is active (`f217011` = this release, `890b42c` = the preceding rc28 build, live since 2026-09-08 14:05 UTC) · NATIVE MOBILE: DEVELOPMENT.**
This release supersedes the prepared-but-never-published v1.9.0 (its entry follows below for the record; no v1.9.0 tag or release exists publicly). The rc29 activation on the hosted deployment is recorded in the private release ledger; schema 011 is unchanged, so rc28 remains a schema-compatible rollback image and every write made under either build stays readable by the other. The corrections come from an independent read-only review of the LIVE rc28 stack by a separate AI reviewer (internal review — not an external audit) plus one further defect found while re-verifying those corrections. Security assurance stays INTERNAL and evidence-based; nothing here is externally audited and no external audit is part of the process.

### What changed for live users (mainnet exposure)

- **Webhook target policy (review finding LS-04, medium)**: outbound webhook destinations are judged on the eight 16-bit groups of EVERY IPv6 spelling (compressed / expanded / zero-padded / dotted-embedded), so hex or expanded IPv4-mapped forms of loopback, private, link-local, CGNAT or metadata targets can no longer bypass the private-destination policy. v4-compatible, SIIT, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001:0::/32`), ORCHID, site-local, discard-only and documentation ranges are denied conservatively; real global addresses adjacent to the documentation prefix (`2001:db81::/32` …) are no longer refused. `server/src/events-delivery.js`; RED-first `sdk/test/rc28-webhook-target.test.js`, `sdk/test/rc29-webhook-dns-transport.test.js`.
- **Webhook DNS transport (rc29; pre-existing functional defect found by the second read-only review)**: on Node ≥ 20 every webhook endpoint addressed by a DNS hostname failed to connect — the guarded lookup did not honour net's `{ all: true }` lookup contract — so hostname endpoints dead-lettered after their attempts and the advertised DNS-rebinding pin never ran (fail-safe direction: no forbidden dial). The lookup now resolves the full answer set, refuses when ANY answer is forbidden (Happy-Eyeballs never races a private address) and dials exactly the validated addresses. Production impact: the live deployment reported zero active webhook endpoints at every observation; no customer delivery was affected.
- **SDK / mobile HTTP client (LS-05, medium)**: a response-body transport failure, or an invalid JSON body after a successful HTTP status, now surfaces as `PolicyVaultNetworkError` carrying the original `Idempotency-Key` (previously a raw exception lost the key, and a retry with a fresh key could repeat a server-side mutation). No route is auto-retried; a same-key retry recovers the recorded outcome only on idempotency-supported routes — the secret-bearing identity / webhook / notification routes require inspecting the existing resource first (`sdk/src/http-client.js`, `sdk/types/http-client.d.ts`). **Installed SDK and mobile clients must upgrade to receive this — the hosted deployment alone does not update them**; `mobile/www/vendor/http-client.js` is regenerated from the same source. `sdk/test/rc28-http-body-failure.test.js`.
- **Legacy same-effect completion ownership (R8-09 extension, medium; pre-RC27F v0.7 records only — none exist on mainnet)**: direct public submission of an unattempted SIGNED sibling of a request this system already completed (one txid, two legacy finalizations) is refused BEFORE any RPC or completion write — it can no longer be marked `CHAIN_VERIFIED` or take the original's keyed receipt; already-damaged both-`CHAIN_VERIFIED` pairs preserve the existing fully validated receipt representative (the runtime never guesses which signature witness was broadcast); a genuinely settled negative sibling no longer strands a valid retry. `sdk/src/wallet-requests-v7.js`; `sdk/test/rc28-live-stack-recovery.test.js` on real df68a1f-produced fixtures (`sdk/test/fixtures/legacy-df68a1f/`). The earlier "no supported exit" statement for the crash-before-broadcast legacy shape (R8-10) is withdrawn on counter-evidence: retain ONE request and re-invoke its normal public submission (`POST /api/v1/wallet/v7/requests/:id/submit`) after the minimum observation age — complete acceptance coverage, repeated funding/output checks and exact mempool absence settle `NOT_BROADCAST`; waiting alone does not.
- **Recovery / succession explanations (UX-08 residual, low)**: shared help, owner-change summaries and confirmation warnings now agree with the actual rules — with succession enabled, funds are not "locked forever" when recovery is off; the owner-change summary uses the root's real successor and fixed delays; heartbeat / unfreeze language names the approval quorum (M of N of the installed set), never "all owners"; succession keeps a previous owner only if that key is listed again. `web/org-root-ui.js`, `core/explain/org-root-explain.js` (regenerated `web/core-bundle.js`, `mobile/www/vendor/core-bundle.js`); `web/test/org-root-setup.test.js`.

### Distribution and build integrity

- **Apache-2.0 `LICENSE` and `NOTICE` ship inside the container image (`/app/LICENSE`, `/app/NOTICE`) and inside the `policyvault-mcp` npm package** (LS-02); `mcp/tools/check-license.js` refuses to pack unless both are byte-identical to the canonical files; `deploy/Dockerfile` and the deterministic source bundle (`deploy/pipeline/bundle-source.sh`) include them. Third-party notices are unchanged; nothing is relicensed.
- **Privacy-safe runtime artifacts (LS-01)**: the pinned native tools (`silverc`, `pv_call_encoder`, `pv_vm_preflight`, `pv_tx_probe`) and the kaspa WASM SDK are rebuilt from the same pinned upstream sources (silverscript `d25bd342…`, rusty-kaspa `cfafeb4c…`, Rust 1.96.1, wasm-pack 0.15.0) with neutral source paths (`--remap-path-prefix`) and only non-allocated debug sections stripped — the previous image carried the build machine's private filesystem paths inside five compiled artifacts (a privacy defect; no secret value and no publicly served binary were involved). Six tracked pins (`deploy/vendor-pins.sha256`) now bind the native AND WASM bytes: `tools/build-private-safe-vendor.sh` (fresh output only), `tools/stage-vendor.sh` (fresh stage only, never overwrites), `tools/verify-image-vendor-pins.sh` (exactly six pins).
- **Fail-closed artifact privacy scanner** (`tools/artifact-privacy-scan.py` behind `tools/image-privacy-scan.sh` and `tools/audit-public-candidate.sh`): traverses every image layer including deleted / whiteout content, metadata, nested archives and compressed payloads; binds declared compression, tar structure, uncompressed `diff_ids` and the referenced application identity; exact path / SHA / family / count classifications; incomplete coverage FAILS. The previous scanner's clean result on the rc28 image is withdrawn for the compiled-path property. Unit controls: `tools/test_artifact_privacy_scan.py`.
- **Rollback / recovery guidance (LS-03)**: `deploy/pipeline/deploy-by-digest.sh` now prints that its image switch does not restore or migrate the database; forward repair, a maintenance boundary, a fresh protected backup and an isolated restore target replace the former image-only rollback across a schema boundary (private runbook). Self-hosting: `deploy/selfhost.sh` requires a verified privacy-safe vendor stage and refuses raw toolchain copies (`docs/selfhost-quickstart.md`).

### Tests and evidence (automated / internal — never human acceptance)

- Automated gates (every result with unchanged before/after source fingerprints; automated / internal evidence only). On the Codex-reviewed correction bytes (`543a392` … `04ec054`, whose runtime files are byte-identical to `f217011` except `server/src/events-delivery.js`): full SDK + live PostgreSQL 1,388 pass / 0 fail / 1 prerequisite skip (the HD private-encoder rebuild lacked a copied lockfile; closed by a prerequisite-complete targeted run 16/16, 0 skipped — the skip is not folded into an invented no-skip total), web 798/798, core (whole `core/`) 1343/1343, mobile 98/98, SDK delta 36/36, MCP 58/58 including the exact `policyvault-mcp@1.5.0` tarball clean-consumer proof, neutral-vendor VM 67/67 on the real TxScriptEngine with the pinned privacy-safe encoder, recovery controls 22/22, artifact-privacy-scanner controls 13/13, core-bundle and mobile-portable byte-identical. On `f217011`: webhook / notification suites 44/44 with live PostgreSQL (the new DNS-transport test 3/3 RED on the previous module, GREEN on the correction), `tools/test_artifact_privacy_scan.py` 13/13, `sdk/test/image-scan-classify.test.js` 4/4; image `fullscale-rc29` (buildId `f217011`): two byte-identical builds, six vendored native/WASM pins byte-identical, fail-closed layer/metadata/nested-payload privacy scanner PASS with every match exactly classified, extracted-rootfs audit 0 findings / 0 hashed known-value hits, hosted boot with the migrations inside the container (schema 011, readiness 200, served bytes == source, anonymous build refused 401), the image's `/app` file set differs from the Codex-verified neutral image in exactly `server/src/events-delivery.js` and from the live rc28 image in 10 changed + 2 added files (`LICENSE`, `NOTICE`); the public-tree reproduction results are recorded in the release packet.
- Browser: headless-Chromium signed harness on the EXACT `fullscale-rc29` image (TEST-ONLY dev signer, testnet-10, tmpfs data): 212/212 checks, 0 uncaught page errors, served bytes == the build tree before and after the run, buildId `f217011` — and identically 212/212 on the Codex-verified neutral image the release was re-verified from; the UX-11 injected-page-error self-test fails as intended on both (64/65, the only failure is the injected uncaught error); the rooted-vault owner-operation lifecycles ran with independent kaspad checks within the recorded finite testnet-10 transaction bound. Signed-out first-run smoke at 1280 px and 375 px on the exact image: 7/7, 0 page / console errors. No real-wallet or human evidence is claimed.
- Independent read-only reviews (internal AI reviews, not audits): the post-launch live-stack review of the running rc28 deployment (findings LS-01…LS-05, the R8-09 extension and the UX-08 residual; R8-10 withdrawn) and a narrow read-only review of the rc29 corrections (which found the DNS-transport defect). Every finding was corrected RED-first with a permanent regression.

### Not in this release / limitations

- Native mobile stays DEVELOPMENT. No real-wallet (KasWare) evidence is claimed by automation; the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD / KAS candidates are testnet-only; the mainnet-creatable generation stays `policyvault-0.4.1`. `policyvault-mcp@1.5.0` (source in `mcp/`, with the corrected client and the license/notice files) — its npm publication status is stated in the README. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry OFF. The KIP-9 storage-mass upstream write-up is prepared but not posted.

## v1.9.0 — PRODUCTION RELEASE `fullscale-rc28`: organizational M-of-N owner root (v0.7, byte-frozen) with browser initiation of rooted-vault owner operations, the RC27 durable-completion model, hosted tenancy for every route family, generation gate, MCP 1.5.0 (org-root tools)

> Prepared 2026-09-08 for the rc28 deployment and staged locally; never published as a tag or release — superseded before publication by v1.9.1 above (the rc28 build it describes was live from 2026-09-08 14:05 UTC until the rc29 activation).
**WEB/AGENT PRODUCTION: LIVE (`fullscale-rc28`, buildId `890b42c`, image `sha256:fe90f1153d0bef29b81fb4cdf39337df3b3c5e465efa57e6ee07a88f664bdee8`) · NATIVE MOBILE: DEVELOPMENT.**
This release is the FIRST production deployment since `fullscale-rc8` and publishes, in one step, the source of the three prepared-but-never-published candidates v1.6.0, v1.7.0 and v1.8.0 (their entries follow below, unchanged) plus everything since. The hosted deployment at https://app.policy-vault.org now serves THIS source (schema 011; the pre-migration backup and the compatible rollback path are recorded in the private ledger). Security assurance for this release is INTERNAL only — independent internal AI falsification reviews of the exact candidates (rounds 3–8), hostile/adversarial matrices, RED-first reproductions, production-byte and live testnet-10 evidence, and the owner's own live mainnet validation after deployment; nothing here is externally audited and no external audit is part of the process.

### Mainnet exposure — what changed for live users

- **rc8 security findings closed on production** (`docs/postlaunch/rc11-internal-review-remediation.md`, `mainnet-exposure-audit-rc11.md`): hosted BUILD AUTHORITY (every hosted build/create/simulate requires the signed-in wallet or its machine credential; the genesis signer must be the caller; a bounded compiled-artifact cache replaces unbounded temporary storage), own-property version/action lookups with explicit `UNKNOWN_VERSION` refusals, and the **mainnet-creatable generation allowlist = `policyvault-0.4.1` only** (`GENERATION_NOT_MAINNET_AUTHORIZED` for everything else — v0.4, v0.5, v0.6, v0.7 and the HD/KAS candidates are testnet-only and fail closed on mainnet; existing v0.4 vaults stay readable and reconcilable). Hosted tenancy (non-oracle 404 / 403) now covers `/org-roots`, `/wallet/v7`, `/wallet/v5|v6` — every route family, with foreign-tenant probes per family in the suites (`docs/postlaunch/authorization-boundary-inventory.md`).
- **Web client**: the flagship UX pass (guided vault/root setups, canonical amount parsing, truthful pending states, network-identity fail-closed banner), UX-01…UX-14 and R6/R7 closures (pre-sign binding of every consensus field the wallet signs, fee-payer finalization authority derived from the fee input, no hidden relative locks, full agent-rule review), and — new in this release — **browser initiation of rooted-vault owner operations** (change agent rules with the full recipient sets, top up the fee reserve, pause, unpause, emergency-pause under the root's freeze quorum, close & recover to the pinned recovery key) plus reservation/withdrawal guidance (an unsigned request reserves the root and guards its vault; only an unsigned, never-attempted request can be withdrawn; a finalized request resumes its original submission; an attempted one goes through outcome recovery). Rooted-vault operations are TESTNET-ONLY today (v0.7 is not mainnet-authorized); on mainnet the web client offers none of them.
- **Durable completion model (RC27, F-1…F-9)**: a later incomplete delegate completes before earlier root history is judged; a failed inspection never downgrades completed history; a proven negative outcome settles only its own claims (including a narrow removed-initial-anchor rule for a first rejection proven through repeated all-inputs-unspent, exact-mempool-miss and absent-output observations); legacy pointerless records recover without pinning an old root; one process-local queue serializes finalize/slot/signature/submit/reject; typed store keys. Live testnet-10 evidence: six-transaction deposit/delegate recovery demonstration and the recovered original browser request (private evidence, summarized in the packet).

### Covenant

- **`contracts/PolicyVault.v0.7-root.sil` + `PolicyVault.v0.7-payment.sil` — organizational M-of-N owner root and its rooted payment profile, COVENANT-BYTE-FROZEN 2026-09-03** (sha256 `69417514…` / `09cdbb6c…`; generators `tools/gen_v7_root.js` / `tools/gen_v7_payment.js`; freeze record `docs/postlaunch/v0.7-covenant-byte-freeze.md`; adversarial review FREEZE-NOT-FALSIFIED). Rules D1/D2/D6–D9; every counted owner signature SIGHASH_ALL-gated in-covenant; FREEZE (K) is the only lighter quorum and can only freeze; owner recovery and succession land frozen after consensus-enforced relative-age delays; ONE vault operation per root transition. **Status: VM-VERIFIED · SDK/PRODUCTION-BYTE-VERIFIED · TESTNET-VERIFIED (live testnet-10 lifecycle, consensus sequence-lock proof, negatives) · NOT mainnet-authorized.**
- `PolicyVault.v0.7-kas.sil` (rooted KAS profile) and `PolicyVault.v0.7-payment-hd.sil` (hierarchical delegation) — additive CANDIDATES, TESTNET-VERIFIED, NOT frozen, NOT mainnet (`docs/postlaunch/v0.7-kas-profile-readiness.md`, `v0.7-hd-readiness.md`, `hierarchical-delegation-design*.md`).
- Shared-core/SDK pre-sign parity with the covenants is maintained as a permanent invariant (`docs/postlaunch/vm-presign-parity-and-enforcement-matrix.md`, `sdk/test/vm-presign-parity.test.js`).

### Application surface

- v0.7 organizational roots: server routes (`/org-roots`, `/wallet/v7`), SDK request lifecycle (genesis, root actions with at most one vault operation, slot signing through the Universal Signer Interface, finalize by the fee payer, submit, reconcile with dependency-first recovery), web (guided root setup with plain-language governance, exact-policy review, own-slot signing, out-of-band approval import, request lifecycle, the rooted-vault owner-operation panels), MCP tools (`policyvault-mcp` 1.5.0: org-root schema fragments and tools; the adapter now identifies itself with an `x-policyvault-mcp-client` header that the server records only when telemetry is explicitly enabled), execution attestations for v0.7.
- Token surfaces for v0.5/v0.6 (version-aware token vault UI; testnet-only) and the HD candidate surface.

### Tests and evidence (automated / internal — never human acceptance)

- `Automated gates on the build source `890b42c` (SDK-only correction of the round-8-reviewed `e7c0cb6`; every gate with unchanged before/after source fingerprints): full SDK + live PostgreSQL 1379/1379 (0 fail / 0 cancelled / 0 skipped) on `890b42c`; core (whole `core/`) 1343/1343, web 796/796, mcp 56/56 (1.5.0 bytes), core-bundle and mobile-portable byte-identical, mobile 97/97 and VM 589/0 — reused with recorded applicability (no change under `core/`, `web/`, `mcp/`, `server/`, `mobile/`, `tests/vm`, `contracts/`, generators since their runs); image `fullscale-rc28`: two byte-identical builds, vendored pins 4/4, per-layer privacy scan CLEAN, rootfs audit 0 findings, hosted boot + migrations inside the container, mainnet-configured allowlist = `policyvault-0.4.1` only, unauthenticated builds refused; the image's file set differs from the reviewed rc27 image in exactly the two corrected SDK files.`
- Browser: headless-Chromium signed harness on the exact image (dev signer, testnet-10; `212/212 checks, 0 uncaught page errors, served bytes == the build tree, on the exact rc28 image; UX-11 injected-error self-test fails as intended`), including the rooted-vault owner-operation lifecycles with independent kaspad checks; UX-11 injected-page-error self-test.
- Round-8 independent internal falsification review of the exact commit + image (`fullscale-rc27`, `e7c0cb6`): BLOCKED on two legacy-data findings (no funds impact; pre-RC27F v0.7 records, none in production) — corrected RED-first on the reviewer's df68a1f-produced snapshots (`sdk/test/legacy-same-txid-r8.test.js`), the reviewer's re-check found the adjacent shape which the lead closed, the second re-check PASSED, and the corrected source was rebuilt as `fullscale-rc28`: `original review BLOCKED (R8-01 LOW, R8-02 MEDIUM, legacy data only, no funds impact) → corrected RED-first → re-check found R8-09 (MEDIUM, legacy) → corrected → second re-check POLICYVAULT-RC27-R8-RECHECK2-PASS; residual R8-10 LOW pre-existing recorded`.
- Migration/rollback rehearsal (009 → 011 on disposable representative data incl. an incomplete request; rc8 fails closed on 011; restore + rc8 path proven) and a 100-regular-user capacity run on an isolated production-shaped container (`100 authenticated users, 60 min sustained realistic mix + burst on the production compose limits: 36,435 requests, read p95 19.8 ms / p99 1,051 ms, build p95 1,638 ms, 0 × 5xx/timeouts/transport errors, CPU avg 2.7 %, memory max 252 MiB, PG connections max 11 — every declared criterion met`).

### Not in this release / limitations

- Native mobile stays DEVELOPMENT (unit + emulator + portable parity only). No real-wallet (KasWare) account/network-change evidence is claimed by the automated runs; the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD/KAS candidates are testnet-only. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry: implemented, OFF, not enabled. The KIP-9 storage-mass upstream write-up is prepared but not posted.

## v1.7.0 — FLAGSHIP WAVE 1: v0.6 atomic-composability covenant (byte-frozen), Universal Signer Interface v2, execution attestations, MCP usage telemetry (OFF), release-signing tooling, deployment pipeline, self-host + UX correctives

**WEB/AGENT PRODUCTION: LIVE (`fullscale-rc8`, buildId `1c02162`) · NATIVE
MOBILE: DEVELOPMENT · THIS RELEASE IS SOURCE ONLY — NOT DEPLOYED.**

This release changes **no production runtime**. The live hosted deployment
still serves `fullscale-rc8` (buildId `1c02162`); the `server/`, `web/` and
`mobile/www/` sources in this tree are a **prepared successor that has not
been built, deployed, or human-accepted**. Nothing here is externally
reviewed or audited.

### Covenant

- **`contracts/PolicyVault.v0.6.sil` — NEW covenant generation v0.6
  "ATOMIC COMPOSABILITY", COVENANT-BYTE-FROZEN 2026-09-03** (owner
  conditional authorization satisfied by exact mechanical re-verification
  plus an independent adversarial review that returned
  FREEZE-NOT-FALSIFIED). sha256
  `c7c5f22c54a55d933ec8440a28bc2c628b9b99262541d50dbe9ffbdd16ba025c`,
  deterministic generator `tools/gen_v6.js`. One owner-approved
  constant-product pool family; `tokenAgentSpend`, `tokenAtomicSell`,
  `tokenAtomicBuy`, `ownerControl`, `ownerRecover`; swaps pinned to
  exactly four inputs (no external fuel input is admissible); SIGHASH_ALL
  gate; 24,920-byte redeem; 5 static sig-ops.
  **Status: VM-VERIFIED (`tests/vm/tests/v6_production.rs`, real
  TxScriptEngine) · SDK/PRODUCTION-BYTE-VERIFIED
  (`tests/vm/tests/v6_sdk_integration.rs`, 36 vectors) · TESTNET-VERIFIED
  (live testnet-10 SELL + BUY lifecycle).**
  **Exact limitations, stated up front: FIXTURE VENUE ONLY** — the only
  swap counterparty proven is the repository's own conformance pool
  fixture (`contracts/experiments/V6PoolFixture.sil`, which is a test
  fixture, **not** a PolicyVault product and not an endorsement of any
  venue); **no real DEX venue is supported, there is no mainnet swap, and
  there is no server/web/mobile/MCP surface for v0.6**; `deadlineDaa` is a
  **pre-sign boundary, not a consensus expiry**; swaps are **not
  economically viable below roughly 10 KAS** (flat cost ≈ 0.0816 KAS —
  `docs/postlaunch/v0.6-economic-viability.md`); period budgets in
  v0.3–v0.6 rely on the shared-core `periodLengthDaa > 0` invariant,
  now pinned by
  `core/model/test/period-length-positive-invariant.test.js`.
  Freeze record `docs/postlaunch/v0.6-covenant-byte-freeze.md`; pin
  `sdk/test/covenant-freeze-v6.test.js`. **PolicyVault is not a DEX and
  will not become one** — it authorizes, verifies intent deterministically
  and enforces policy; liquidity and execution stay external
  (`docs/postlaunch/roadmap-dex-adapter-and-protocol-evolution.md`).
- Unchanged bytes: v0.5 `c693aeff…`, v0.4.1, v0.4, v0.3, v0.2,
  v0.1.beta. No frozen covenant was regenerated or edited.
- New shared-core and SDK layers for v0.6: `core/model/{vault-state,
  agent-merkle,swap-policy,vault-transitions,compute-budget}-v6.js`,
  `core/model/storage-mass.js`, `core/intent/{token-manifest,
  swap-manifest}-v6.js` and the fail-closed `core/intent/router.js`;
  `sdk/src/{contract-compiler,vault-builders,swap-pool-fixture,
  vault-state,vault-transitions,agent-merkle,swap-policy,
  compute-budget}-v6.js`. Leaf fixtures are pinned byte-for-byte to the
  Rust leaf functions the real engine accepts
  (`tests/vm/tests/v6_fixture_capture.rs`).

### Universal Signer Interface v2 (additive; nothing migrated to it yet)

- **`core/signer/v2/` — `policyvault-signer/2`: IMPLEMENTED ·
  UNIT-TESTED · ADVERSARIAL-TESTED (hostile suite 48/48).** Explicit
  negotiation of sighash type, PSKT support, transaction format,
  user-presence, transport, timeout and cancellation; response envelopes
  bound to the request; a replay guard; and a probe-versus-declared
  capability check that fails closed when a signer's real behaviour
  contradicts what it advertised. Adapters for KasWare, the reference CLI
  signer (real cryptography via kaspa-wasm) and air-gapped transport.
- **Honest limits: no production consumer has been migrated to v2** — v1
  (`policyvault-signer/1`) remains what ships in the app, so v2 is
  additive and inert. **No live independent second wallet has been
  exercised**, and the PSKT / ECDSA wire contracts are deliberately left
  unfrozen pending source-backed evidence. The v2 air-gap adapter is not
  yet wired into the mobile platform layer.
- Fixed: a mobile air-gap envelope serialization defect found by the v2
  conformance suite (`mobile/www/js/portable/airgap.js`).

### Execution attestations (exportable, machine-verifiable outcome records)

- **`core/attest/` — `policyvault-execution-attestation/1`: IMPLEMENTED ·
  UNIT-TESTED · ADVERSARIAL-UNIT-TESTED · API-TESTED.** A canonical,
  hash-addressed record of what was authorized, what was signed and what
  the chain actually did, with the outcome ladder enforced as a
  contiguous prefix and refusal attribution kept narrow. 103 tests
  including 32 tamper classes (naive and re-hashed) and a language rule
  that forbids the words *compliant*, *certified* and *regulator*.
- **`tools/attestation-verify.js`** — an INDEPENDENT verifier: structure,
  expectation binding, and an opt-in **pure** chain re-check that reports
  `CHAIN_CONFIRMED` · `UNCONFIRMED` · `UNAVAILABLE` · `CONTRADICTED`. The
  chain re-check path is TESTNET-VERIFIED against the v0.6 live evidence
  shipped in `docs/testnet-v6-atomic-evidence.json` (that file is also the
  positive test vector for the attestation suite).
- **Server:** `GET /api/v1/attestations/requests/:id` and
  `GET /api/v1/attestations/export` (json / ndjson) behind a NEW
  deny-by-default scope `read:attestations`; SDK client methods declared
  in `sdk/types/http-client.d.ts`.
- **Honest limits:** the signature slot is designed but **has no key** —
  deliberately, because PolicyVault holds no server-side key anywhere near
  funds; the accepting-block DAA score is not persisted in `receipt/v1`,
  so exports state no depth; there is no hosted `VERIFIED_OUTCOME`
  producer yet; exports are v0.4/v0.4.1 KAS-only (token/swap mapping is
  additive future work); no MCP tool and not in the browser core bundle.

### MCP usage telemetry — OFF BY DEFAULT, NOT ENABLED ANYWHERE

- `server/src/mcp-telemetry.js` + `server/migrations/010_mcp_telemetry.sql`
  (`policyvault-mcp-telemetry-event/v1`, create-only category),
  aggregates behind `read:metrics`, client header in `mcp/src/http.js`.
  **Recording defaults OFF** (`POLICYVAULT_MCP_TELEMETRY` unset or
  `"off"`) and is **not enabled in any deployment**; turning it on is an
  operator decision. Includes a privacy-negative byte scan proving no
  vault identifiers, amounts, addresses, credentials or free text are
  recorded, retention pruning and a hard cap. Spec:
  `docs/postlaunch/mcp-usage-telemetry-todo.md`.

### Release signing and succession governance (tooling only — no key exists)

- `tools/release-manifest.js` / `release-sign.js` / `release-verify.js`
  build, sign and verify a `policyvault-release-manifest/1` artifact
  identity (tree hash, covenant hashes, lockfile hashes, optional image
  and archive digests) using OpenSSH `ssh-keygen -Y` signatures against
  the threshold policy in `release-signers.json`.
- **`release-signers.json` ships with ONE signer entry whose public key is
  the literal placeholder `OWNER-TO-FILL`, threshold 1.**
  `tools/release-verify.js` **refuses to count any signature** against an
  unfilled entry. The structure is multi-signer *capable*; it is **not**
  a multi-signer policy today, and no second maintainer exists — the
  onboarding checklist in `docs/postlaunch/release-trust-model.md`
  deliberately names no fabricated person. **No release has been signed.**
- Webhook at-rest key rotation: a written procedure
  (`docs/postlaunch/webhook-secret-rotation-procedure.md`, **NOT
  executed**), a `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS` overlap
  fallback, the `tools/reseal-webhook-secrets.js` resealing tool, and a
  Python HMAC verifier (`python/policyvault_client/webhooks.py`).

### Deployment pipeline (local proof only; production use is owner-gated)

- **`deploy/pipeline/`: DESIGNED · IMPLEMENTED · INTEGRATION-VERIFIED
  LOCALLY (non-production).** A reproducible OCI build
  (`SOURCE_DATE_EPOCH` + timestamp rewrite, provenance/SBOM off;
  bit-reproducible export proven twice; digest-pinned base byte-identical),
  a content-addressed layer delta (**1,382,400 B for a one-file deploy
  versus a 207,922,176 B full image — about 150×**), a signed source
  bundle with a remote-builder fallback, deploy-by-digest with a rollback
  ledger, and verify-before-activate (privacy scan plus a private
  health/readiness probe). Cost: zero. `sdk/test/deploy-pipeline.test.js`.
  **Never run against production**; the first production use is an owner
  decision. Residual: the apt layer is content-equivalent, not
  bit-identical. Rationale and threat model:
  `docs/postlaunch/deployment-pipeline-independence.md`.

### Self-hosting correctives (from an outsider clean-environment re-test)

- **Three genuine first-run defects FIXED:** `tools/stage-vendor.sh` failed
  under `pipefail` when the vendor dist directory was missing (this broke
  *every* first run); undocumented prerequisites now produce actionable
  fail-closed messages with the exact commands; `deploy/selfhost.sh` used a
  constant build-id fallback that broke `upgrade` on git-less checkouts and
  left rollback serving the wrong buildId.
- **New `tools/selfhost-acceptance.sh`** — a 22-step self-host acceptance
  run: real Schnorr authentication, backup/restore into an isolated
  database with row-count and hash verification, upgrade/rollback identity,
  log redaction, host-reboot simulation and a hidden-dependency scan.
  Record: `docs/postlaunch/selfhost-flagship-retest.md`. Known gap:
  wallet authentication end-to-end is NOT tested headlessly (it needs a
  browser and a wallet extension).

### Web and mobile UX pass — UNIT/jsdom-BROWSER tested, NOT human-accepted

- 13 correctives to real adoption failures, not aesthetics: ARIA live
  regions on all six status surfaces; a **closed** 35-code refusal
  explanation table (`web/refusal-explain.js`, no overrides); an outcome
  table driven by the SDK request state where **PENDING is never
  presented as success**; recipient-allowlist disclosure with a real spend
  form (replacing a `window.prompt`); a truthful "one on-chain owner"
  statement; node-problem versus wallet-problem messaging; 375 px
  responsive rules; a visible focus ring; reduced-motion anti-drift; a
  recovery warning; clearer agent naming. Mobile: banner announcement,
  focus handling and 44 px touch targets.
- **No person has operated these screens in a browser, on a device, or
  against production. Human acceptance is not claimed.**

### Shared deterministic core (hybrid local-first)

- **PRODUCTION CODE BUG FIXED:** the browser's KAS→sompi conversion on the
  spend path used floating point — it accepted `0x10` and `1e3`, rounded a
  ninth decimal, turned `0.000000001` into `0`, and lost precision on large
  values. It now goes through the canonical `core/model/amounts` parser via
  the browser core bundle, with 15 recorded defects pinned as refusals and
  a golden parity fixture (`web/test/client-amounts-parity.test.js`).
- `core/intent/token-manifest-v6.js` + `core/intent/router.js` — a
  `policyvault-controller-intent-manifest/1` verifier for v0.6
  spend/owner/recover/deposit with a **fail-closed** version router
  (unknown versions are never routed to a default). Two false-refusal bugs
  in the new verifier were found by real-build tests and fixed.
- A v0.5/v0.6 cross-runtime equivalence battery (44 cases over the 32-file
  closure), and the SDK browser harnesses now load the **real** shipped
  core bundle exactly as `web/index.html` does.

### Not in this release

- The organizational M-of-N owner root (**v0.7**) is DESIGNED and being
  implemented on a separate lane; **no v0.7 covenant, generator or test is
  in this tree**, and none is frozen.
- Hierarchical delegation is DESIGNED only (experimental probe evidence);
  no production covenant, no SDK, no manifest.
- The DEX / swap adapter framework has **no implementation**; its design
  candidate is published as `docs/postlaunch/dex-adapter-design-spec.md`
  and remains gated on an owner design-freeze decision.
- Internal program, planning and acceptance records (readiness matrices,
  wave logs, deployment packets, live acceptance transcripts) are not
  published — see `PUBLIC_RELEASE_MANIFEST.md` for the exact exclusion
  set.
- **No external professional security review or audit has occurred.**

## v1.6.0 — x402 FACILITATOR (Kaspa `exact`/upfront scheme; read-only chain verification / settlement attestation)

**WEB/AGENT PRODUCTION: LIVE (fullscale-rc8, buildId `1c02162`, unchanged by this release) · NATIVE MOBILE: DEVELOPMENT · x402 FACILITATOR: IMPLEMENTED + TESTNET-VERIFIED, not a hosted production service.**

- **New: `integrations/x402-facilitator/`** — a separately deployed,
  unprivileged, READ-ONLY chain verification / settlement attestation
  service for the proposed Kaspa x402 scheme `exact` +
  `extra.paymentFlow: "upfront"` (`pv-x402-kaspa-exact-upfront/1`). The
  payer settles first with an ordinary Kaspa transaction; the facilitator
  checks the exact outpoint against a synced UTXO-indexed node and, on
  `/settle`, records ONE durable single-use claim with the evidence. It
  holds no keys, signs nothing, broadcasts nothing, escrows nothing,
  never calls a PolicyVault API, never emits a 402, and never charges.
  Design frozen by the owner (`docs/postlaunch/x402-facilitator-design-freeze.md`,
  spec revision 3); network identifiers `kaspa:mainnet` /
  `kaspa:testnet-10` are PolicyVault's PROVISIONAL CAIP-2-syntax
  identifiers (no upstream registration is claimed); resource-server
  authentication = facilitator-issued API key over HTTPS with a dedicated
  principal model (mTLS optional future hardening); settlement policy
  `pv-x402-settlement/1` (depth 100 default, hard floor 20, window
  ≤ 36,000 DAA); token payments use the FROZEN v0.5 semantics through
  `core/assets` (both bindings + conservation). PostgreSQL claim store
  (race-proven) and a single-instance JSON store; `/readyz` + `/healthz`;
  launcher + admin CLI; `deploy/x402f/` image, compose overlay and env
  template for self-hosting.
- **New: `sdk/src/tx-identity.js`** — a read-only SDK leaf that
  recomputes a carried transaction's CONSENSUS id through the engine
  (the wasm `deserializeFromSafeJSON` echoes the embedded id and the wasm
  `Transaction` caches its id at construction; the Kaspa txid commits to
  output covenant bindings) — pinned against the Rust `pv_tx_probe`
  hasher (`sdk/test/tx-identity.test.js`).
- `sdk/src/chain.js`: additive `isCoinbase` field on normalized UTXO
  entries (null when the node omits it; consumers fail closed on null).
- `integrations/test/dependency-direction.test.js`: rule 5 — the
  facilitator may import only `core/**`, `integrations/lib/**`,
  `sdk/src/chain.js`, `sdk/src/tx-identity.js`.
- `tools/image-privacy-scan.sh`: SIGPIPE-safe sanity check +
  `PV_SCAN_SANITY_PATH` for non-app images.
- Docs: facilitator spec (frozen), design-freeze record, program record,
  conformance spec §12, adapter spec §1.6 cross-reference, README status
  + layout, SECURITY claim block (CLAIM → ENFORCEMENT → TEST → EVIDENCE).
- Evidence (this tree, all suites green): freeze pin 6 · unit 14 ·
  hostile matrix 34 · service/auth 12 (+ readiness 1) · PostgreSQL claims
  6 · txid production-byte 3 · dependency direction 8; live testnet-10
  proof (real KAS + real frozen-v0.5 token payments; evidence retained
  privately). Honest ecosystem statement: no upstream Kaspa x402 scheme
  exists; the facilitator is not "x402-compatible" beyond the proposed
  scheme. No external security review has occurred.
- Unchanged: covenant bytes (v0.5 `c693aeff…`, v0.4.1, v0.4, v0.3),
  the production web/API surface, MCP 1.4.2, mobile.

## v1.5.0 — v0.5 token-controller covenant (byte-frozen), least-privilege discovery + console correctives (fullscale-rc8), MCP 1.4.2, illustrated onboarding

The corrective + v0.5 successor to v1.4.0. Production runtime successor
**`fullscale-rc8`** (buildId **`1c02162`**, built from the v1.3.0/v1.4.0
production source `6c3177f` + ONLY the six-file server/web corrective
delta) — **LIVE** — deployed and accepted on automated evidence on 2026-09-02 (production acceptance 46/46 through the public edge + successor-specific live checks; the owner validates the console independently; no human acceptance test is claimed). The v0.5 covenant, SDK, and core layers ship as
SOURCE (frozen, VM- and testnet-verified) — no v0.5 server/API/web surface
exists yet and no v0.5 vault exists on mainnet. Schema (009), webhooks,
custody/signing architecture, and the frozen v0.4 / v0.4.1 covenant bytes
are unchanged; the covenant/VM toolchain binaries in the production image
are byte-identical to v1.3.0's.

### Added — v0.5 TOKEN CONTROLLER covenant (COVENANT-BYTE-FROZEN 2026-09-02)
- `contracts/PolicyVault.v0.5.sil` — sha256
  `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9`,
  regenerated byte-identically by `tools/gen_v5.js`; one instance per
  (vault, accepted asset descriptor, accepted template); owns a KCC20 token
  position and authorizes delegated TOKEN-denominated agent spends under
  per-agent caps, period budgets and recipient allowlists, with its own KAS
  held exclusively as a covenant-accounted fee reserve (two-domain
  accounting); owner pause / unpause / recover. Carriage:
  TRANSACTION-DERIVED VERIFIED TEMPLATE CARRIAGE (dual binding: covenant-ID
  + hash-verified template + pinned geometry). Spec
  `docs/covenant-spec-v0.5.md`; design freeze, independent internal
  reread, readiness synthesis and the freeze record under
  `docs/postlaunch/v0.5-*.md`. `sdk/test/covenant-freeze-v5.test.js` pins
  the frozen identities (covenant, generator, vendored KCC20 program).
- Vendored KCC20 reference program `contracts/vendor/kcc20-reference.sil`
  (byte-exact upstream; sha256 `2b7d59b0…`), canonical token parsing
  (`core/assets/`: kcc20 state codec, redeem split/reconstruct, static
  sig-op scan, BLAKE2b, `policyvault-asset-descriptor/1` validation and
  template corroboration), v0.5 model/intent/explain modules (`core/model/*-v5.js`,
  `core/intent/token-manifest-v5.js`, `core/explain/token-explain.js`),
  SDK builders/manifests (`sdk/src/*-v5.js`, `token-program-kcc20.js`),
  and the browser/mobile core bundles rebuilt with the assets layer
  (byte-identical to each other; anti-drift pinned).
- Evidence labels (exact): VM-VERIFIED on the real engine with production
  encoder bytes (`tests/vm/tests/v5_production.rs` 37-case hostile spend
  matrix, `v5_sdk_integration.rs` production-byte vectors);
  TESTNET-VERIFIED — one full live testnet-10 lifecycle (issuance →
  descriptor → controller genesis → deposit → agent spend → two
  consensus-rejected negative-validation transactions constructed
  independently of the application → pause → unpause → recovery), every
  outpoint chain-verified through the node's UTXO index; the txids are
  recorded in `docs/postlaunch/v0.5-covenant-byte-freeze.md`. NOT
  production, NOT externally reviewed.

### Fixed — least-privilege capability discovery (server + MCP 1.4.2)
- `GET /api/v1/capabilities` now names the PRESENTED machine credential's
  own principal (identity id + granted scopes) and advertises
  `features.principalScopedDiscovery`; anonymous / browser callers receive
  the byte-identical public document; an invalid presented credential is
  refused (401 `MACHINE_TOKEN_INVALID`) — never downgraded to anonymous.
  Server-side scope enforcement was never affected (a hidden tool called by
  exact name is still refused 403 `SCOPE_FORBIDDEN`); this closes a
  DISCOVERY gap, not an authorization bypass.
- `policyvault-mcp@1.4.2`: presents its credential at discovery and
  advertises ONLY the tools whose scopes are granted (a `read:network`-only
  credential lists exactly `policyvault_capabilities` and
  `policyvault_network_status`); malformed discovery and refused
  credentials fail closed at startup with the server's own code; legacy
  servers fall back to the build-level catalog with a stderr notice. Exact
  tarball identity: sha256 `2f9ff1b85d9097128a7936f503d15418e5b7157e5730e599dfed2fcc9519768e`,
  npm shasum `e33bcc6549c662a0d1b098f68efb6fdd4d5d063f`. Proof tooling:
  `mcp/tools/candidate-proof.js` (exact-tarball clean consumer + real
  server), `mcp/tools/remote-proof.sh` (public artifact clean-room proof).
- `policyvault-mcp@1.4.1` packaging correction is carried in source: the
  package resolves its shared core through a sha256-pinned verbatim copy
  (`mcp/core/`, `mcp/tools/sync-core.js`, `mcp/test/core-sync.test.js`,
  `package-closure`/`package-consumer` gates) — 1.4.0's standalone
  topology was broken and is deprecated on npm.

### Fixed — production web console (owner-live findings 2026-09-02)
- No `/wallet/dev-accounts` probe on production: the mock signer is
  offered only when `/health` advertises `devSigner:true` (testnet +
  `POLICYVAULT_DEV_SIGNER=1`, never mainnet; shared server predicate).
- WALLET CONNECTED ≠ SESSION AUTHENTICATED: a connected wallet with a
  signed-out hosted session issues zero privileged reads (quiet sign-in
  states on every view); an auth refusal while believed authenticated
  triggers exactly one server-truth re-read (`revalidateAuth`) and no retry
  loop; 401 stays a genuine refusal.
- Wallet public-key normalization diagnostics are opt-in
  (`localStorage pv.debug=1`); public material only — seeds, keys, bearers
  and session secrets were never logged and still are not.

### Added — illustrated onboarding (presentation only)
- The six-step first-run walkthrough is now illustrated (system flow,
  create/control, rules, bounded delegation, accepted vs refused, key
  distinction) with theme-token colours, reduced-motion-safe animation,
  keyboard-reachable replay and accessible labelling. Semantics unchanged:
  skippable everywhere, "don't show again", Help replay, verbatim authority
  statement, no key request, never gates any action.

### Added — roadmap
- `docs/postlaunch/roadmap-dex-adapter-and-protocol-evolution.md`: the
  post-v0.5 sequence (x402 FACILITATOR → DEX / Swap Adapter Framework →
  …), the product boundary (PolicyVault MUST NOT become a DEX; external
  liquidity/execution; external signers; fail-closed adapter verification
  surface) and the permanent Kaspa Protocol Evolution Compatibility program
  (vProgs/DAGKNIGHT foresight, consensus-upgrade freeze-reopen rule,
  additive migration invariant).

### Status labels carried (unchanged discipline)
- WEB/AGENT PRODUCTION: LIVE. NATIVE MOBILE: DEVELOPMENT (not
  production-capable; APK identities carry unchanged from v1.3.0 — `mobile/`
  runtime is unchanged apart from the vendored core bundle used by the
  portable verification layer). No external professional security audit has
  occurred; nothing in this repository claims otherwise.

## v1.4.0 — Distribution: MCP registry packaging, agent examples, one-command self-hosting

A source/distribution release: **no runtime change and no production
deployment** — every directory the production container copies
(`core/ sdk/ server/ web/ contracts/`) is byte-identical to v1.3.0
(live buildId `6c3177f` unchanged). The adoption-first program's first
three deliverables ship here.

### Added — MCP distribution (official registry + npm)
- `mcp/package.json` is npm-publishable (`policyvault-mcp`; zero runtime
  dependencies) with the official MCP registry ownership binding
  (`mcpName: io.github.zapsoblige-hash/policyvault`), and
  `mcp/server.json` carries the registry metadata (stdio transport,
  environment variables with secret marking, authority statement).
- `docs/postlaunch/mcp-distribution.md`: install, transport,
  configuration, auth setup, read-only vs mutation semantics, network
  guidance, example prompts, version compatibility, and fail-closed
  behavior. The MCP layer remains a thin distribution surface over
  existing capability — it implements no financial semantics, holds no
  keys, and gains no authority from being packaged.

### Added — agent-framework examples
- `examples/agents/`: thin wiring for the OpenAI Agents SDK, LangChain,
  and CrewAI that attaches an existing agent to PolicyVault through the
  MCP server only. No adapter contains financial logic; the README
  carries the authority statement, minimal-scope credential guidance,
  simulate-before-create discipline, and untrusted-data rules.

### Added — one-command self-hosting
- `deploy/selfhost.sh` (init / up / check / acceptance / upgrade /
  rollback / backup / restore / down / destroy) with
  `deploy/docker-compose.selfhost.yml` and `docs/selfhost-quickstart.md`.
  Equal-security by construction: testnet-10 default; mainnet requires
  the same dual unlock as hosted production, an https origin, and a
  TLS-capable PostgreSQL (the app refuses no-TLS postgres on mainnet);
  generated config is mode-600 with a random database secret; dev/test
  flags are never written; the self-check verifies release identity,
  network equality, node sync + utxoindex, posture, and the structural
  absence of wallet secrets.

### Added — research transparency
- `docs/postlaunch/v0.5-token-d1-spike.md`: the v0.5 token-support D1
  research spike (KCC-0001/0002/0020 and current node-source findings),
  with every claim labeled SOURCE-VERIFIED / SPEC-VERIFIED / DESIGN
  TARGET / OPEN — nothing frozen, nothing VM-proven yet, and the
  required dual binding (controller authorization + hash-verified
  template pinning) recorded as a non-negotiable design constraint.

### Notes
- No schema, webhook, auth, or consensus change of any kind. No
  external security audit has occurred; nothing here claims one.

## v1.3.0 — Bearer wallet-sessions + native mobile production transport

The native-mobile/bearer successor to v1.2.0 (production buildId
`6c3177f`, built on the v1.2.0 production source `5b90e74`). The server
delta is bearer-session code only (additive, config-gated); the client
delta is the mobile app: the full validated Capacitor Android project
with an explicit native HTTP transport. Web client, covenant, schema
(009), webhooks, and all consensus-visible bytes are unchanged —
the covenant/VM toolchain binaries in the production image are
byte-identical to v1.2.0's.

### Added — bearer wallet-sessions (server, config-gated, default OFF)
- `POST /auth/verify` accepts an explicit `transport: "bearer"` and,
  ONLY when `POLICYVAULT_AUTH_BEARER_SESSIONS` is enabled, returns the
  wallet-session token in the response body instead of setting a
  cookie. Without that flag — or without the explicit request — the
  route is byte-identical to the cookie-only behavior. Live production
  has the flag enabled as of this release.
- Authentication only, never authority: a bearer session grants the
  same tenancy/read/coordination access as the cookie session and, like
  it, is never consulted for signing authority. Custody stays with
  wallet signers; the server still holds no keys.
- Fail-closed resolution order, proven by suite + live acceptance: an
  explicitly presented invalid bearer refuses as an invalid session
  (never an anonymous downgrade); machine-credential-shaped
  `Authorization` values stay on the machine-credential path (strict
  separation); wrong-network wallets are refused at challenge;
  challenge nonces are single-use (replay refused); `POST /auth/logout`
  revokes a presented bearer server-side
  (`sdk/test/hosted-auth-bearer-sessions.test.js`).

### Added — native mobile production transport (Android)
- The mobile app now ships the full Capacitor Android project
  (`mobile/android/`) with an explicit native HTTP transport
  (`mobile/www/js/platform/native-http.js`, CapacitorHttp at the
  platform seam — no global fetch/XHR patching). The hosted API keeps
  its strict same-origin/no-CORS posture: no CORS grant exists or is
  required; the web client's browser security model is unchanged.
- The native adapter declares its request origin explicitly
  (documented programmatic-client contract with the hosted origin
  wall); the packaged WebView itself cannot reach the API cross-origin.
- Wallet sign-in on mobile uses the existing air-gap QR framing +
  manual-paste signature transport with the offline CLI signer
  (camera capture is not built; paste-only v1). The bearer token is
  held memory-only — never persisted, never logged by the app, never
  in a URL — and an app restart is signed out by design.
- Validated on a real Android emulator against live production:
  reads, the complete UI-driven bearer lifecycle (challenge → offline
  CLI signature → verify → authenticated read → sign out → server-side
  revocation), and the adversarial matrix (malformed/revoked bearer,
  wrong network, wrong signer, nonce replay). Android release signing,
  store packaging, and camera capture remain pending — native mobile
  stays DEVELOPMENT, not production-capable.

### Notes
- No migration: schema stays 009. No webhook, rate-limit, or
  cookie-auth change. `mobile/test/native-http.test.js` and
  `sdk/test/hosted-auth-bearer-sessions.test.js` are the new suites;
  all existing suites carry unchanged.
- No external security audit has occurred; nothing here claims one.


## v1.2.0 — Responsive client orchestration + quiet signed-out state

A client-orchestration/presentation successor to v1.1.1. No server,
schema, covenant, signing, or authentication-semantics change — the
runtime difference is exactly five `web/` files (two application files,
three test files) plus the build identity.

### Fixed — signed-out UX (hosted deployments)
- A fresh signed-out visit no longer shows the spurious
  "Organizations unavailable: sign in to use this route" toast: on a
  hosted server the client simply does not request privileged data
  (organizations, vaults) until an authenticated session exists, and
  shows quiet inline states instead ("Sign in to view your vaults." /
  "Sign in to use Organizations."). An auth refusal that still occurs
  while signed out (races) renders the same quiet state.
  AUTHENTICATED failures and all non-auth errors surface exactly as
  before; self-hosted (authMode disabled) behavior is unchanged;
  authentication semantics are untouched.

### Improved — responsiveness (client orchestration only)
- Startup parallelized: the network probe, hosted-session restore, and
  session-gated data loads run concurrently (the wallet reconnect still
  awaits the authoritative network identity first — that ordering is a
  correctness property). One `/health` request at startup instead of
  three.
- Views retain their last-good data bound to an identity epoch (wallet
  address + wallet network + session status): returning to a tab paints
  immediately with a truthful "Refreshing…" marker while an
  authoritative background refresh runs. Wallet, account, network, and
  session changes discard every retained entry and shared in-flight
  read; a response that started under an older identity is discarded
  (never painted, never cached). Cold views paint "Loading …"
  immediately.
- The vaults view's independent reads (vaults, organizations, open
  approval requests, governance proposals) run concurrently, with the
  per-vault suspension reads following as before (fail-closed
  suspension rendering preserved verbatim); serial depth drops from
  4–5 round-trips to 2. The Organizations view is parallelized the same
  way.
- Concurrent identical GETs share one in-flight request (never a
  response cache; mutations are never deduplicated). The
  network-identity banner probe deliberately bypasses this sharing so a
  self-heal retry can never be absorbed by a hung earlier probe.
- Signing in prefetches organizations + vaults and re-renders the
  dashboard (previously nothing re-rendered after sign-in).
- Immediate truthful progress states on financial actions:
  "Preparing transaction…", "Waiting for KasWare…",
  "signed — submitting…". **Pending is not success**: only the existing
  authoritative CHAIN_VERIFIED outcome renders as success, and every
  fail-closed path (RECONCILIATION_REQUIRED included) is unchanged.
- The wallet-invocation path was audited and carries zero unrelated
  awaits (fuel selection, transaction build, review, and the mandatory
  browser verification are all required inputs/gates); a regression now
  pins that unrelated reads cannot delay the wallet popup.

### Tests
- `web/test/ux-responsiveness.test.js` (new): 18 browser regressions —
  the signed-out matrix, identity-epoch invalidation (wallet / network
  / session), stale-response protection, in-flight dedupe, read
  parallelism, signing independence from unrelated reads, wallet
  rejection, and pending-is-not-success.
- `web/test/network-banner.test.js`: probe-source assertion follows the
  banner's dedupe exemption; `web/test/network-strings.test.js`:
  pinned line numbers updated.

## v1.1.1 — Truthful, fail-closed network-identity banner

A minimal, presentation-only successor to v1.1.0. Its single product
change fixes a production presentation defect: the web client's top
banner was a hardcoded `TESTNET-10` warning that was only corrected
after a *successful* network-status probe — so a MAINNET deployment
whose node probe failed kept displaying a stale, false network
identity.

### Fixed — web client only
- The banner now derives ONLY from `GET /api/v1/network/status` — the
  node-verified network identity (server-side `connectVerified`: node
  network == configured network, synced, utxoindex), which is the same
  server-reported identity the wallet signing gate compares against.
  It is never derived from the hostname, a build-time constant, or
  cached markup.
- Initial markup is a neutral `VERIFYING NETWORK…` state (it never
  names a network before one is verified).
- Resolved mainnet → a restrained `MAINNET — real KAS` indicator;
  resolved testnet → the explicit
  `<NETWORK> — no real value · mainnet broadcasting is disabled`
  warning; failed / malformed / pending →
  `NETWORK STATUS UNKNOWN — verify connection before transacting`
  (fail closed — never a stale or guessed network).
- Stale-response guard: a late response (any outcome) can never
  overwrite a newer resolution, in either direction. Bounded retry
  after failure (15s → 30s → 60s cap, stops at first success), so open
  pages self-heal after a transient node outage.
- The hosted-staging `NON-PRODUCTION` label now owns the banner
  outright — network resolution can never overwrite it.
- The pre-JS `#v4-root` placeholder and an HTML comment no longer name
  a network.

### Tests
- `web/test/network-banner.test.js` (new): 18 browser regressions
  evaluating the real production `app.js` — mainnet / testnet /
  pending / failure / malformed / retry-recovery / bounded backoff /
  stale-response ordering / staging ownership / signing-gate
  byte-identity / authoritative-source-only.
- `web/test/network-strings.test.js`: the hardcoded-network-string
  regression net now also covers `index.html` (pinned to zero
  occurrences).

### Changed
- Nothing else. The runtime difference between the v1.1.0 production
  image and this release's image is exactly four `web/` files plus the
  build identity: `web/index.html`, `web/app.js`,
  `web/test/network-banner.test.js` (new),
  `web/test/network-strings.test.js`. The wallet network verification
  gate (`verifyNetwork()`) is byte-identical — signing remains
  unavailable wherever it already required a verified network.
  Covenant bytes, transaction construction, signing, wallet adapter,
  server authentication, tenancy, policy enforcement, and the database
  schema (009) are unchanged. No CSP change. No dependency change.

## v1.1.0 — In-app documentation discovery

A minimal, presentation-only successor to v1.0.0. Its single product
change is making the documentation site, https://docs.policy-vault.org,
discoverable from inside the application.

### Added — web client only
- Persistent **Docs** link in the application header (new tab,
  `rel="noopener noreferrer"`).
- Nine contextual help affordances deep-linking to verified
  documentation pages: seven concept links in the vault-creation form
  (fee reserve, agent/delegate, per-transaction limit, periodic budget,
  destination allowlist, approval threshold, external approver) and two
  vault-action help icons (pause/revoke, owner recovery). All link
  targets are static literals verified against the live documentation
  site; titles are escaped; anchors never leak an opener or referrer.
- Three regression tests pinning the feature (header link, a real
  render of the creation form proving exactly the expected links, and
  the action-icon/helper shape).

### Changed
- Nothing else. The runtime difference between the v1.0.0 production
  image and this release's image is exactly four `web/` files plus the
  build identity: `web/index.html`, `web/app-v4.js`,
  `web/test/app-v4-gate.test.js`, `web/test/network-strings.test.js`
  (proven by a full per-file SHA256 manifest of both container
  filesystems, 11,626 files each). Covenant bytes, transaction
  construction, signing, wallet adapter, server authentication,
  tenancy, policy enforcement, and the database schema (009) are
  byte-identical to v1.0.0. No CSP change. No dependency change.

## v1.0.0 — Web/Agent Production Release (from v0.4.1)

The platform around the (unchanged) v0.4.1 covenant grew from a self-hosted
single-user application into the full Web/Agent production system now serving
https://app.policy-vault.org. The covenant protocol itself is **unchanged**:
`contracts/PolicyVault.v0.4.1.sil` is byte-identical to the v0.4.1 release
and regenerates identically.

### Added — deterministic core (`core/`)
- Portable shared core extracted from the SDK: model (Merkle trees, state
  commitments, fee/mass, frozen transactions, compute budgets), **intent
  manifests + verification**, human-readable explanations, governance
  classification + canonical digests, risk composition, signer protocol —
  byte-equivalent across Node, browser, and the mobile scaffold
  (`docs/postlaunch/cross-runtime-equivalence.md`).

### Added — hosted platform (`server/`)
- PostgreSQL persistence with migrations 001–009 (hosted schema, audit
  correlation, governance store, org controls/risk, platform agent API,
  events/webhooks, agent suspensions, hash-chained audit, notifications);
  JSON persistence remains the self-hosted default with full feature parity
  at the store layer.
- Hosted authentication (Schnorr wallet sign-in, Secure cookies), tenancy
  isolation, Origin/CSRF gate, rate limits, body caps, trusted-proxy
  handling (`docs/hosted-request-protection.md`).
- **Governance**: proposal/approval ceremony for authority-expanding policy
  changes, owner-signature-verified over domain-separated digests; proposal
  consumption is terminal. **Risk pipeline**: restrictive-only review/deny
  adapters with exactly-once released-hold continuation.
- **Intent-manifest records**: content-addressed, integrity-re-hashed on
  read, content-bound at finalize; served with live re-verification.
- Budget reservations, idempotency keys, machine identities + scoped
  capabilities, dry-run simulation, capability discovery, hash-chained
  audit with correlation ids, webhooks (HMAC-signed, optional at-rest
  encryption), human notifications, operational observability.

### Added — clients and agent surfaces
- **Browser-local independent verification** (`web/verify-intent.js` +
  `web/core-bundle.js`): full pre-sign re-derivation from the exact signing
  payload, DO-NOT-SIGN rendering, Merkle-root and state-id recomputation.
- Universal Signer Interface + KasWare mapping + offline CLI signer
  reference (verifying `/2` request format).
- MCP server (`mcp/`), Python client (`python/`), x402 and AP2
  payment-protocol adapters (`integrations/`), platform REST API for
  agents; five-path conformance matrix (`conformance/`) proving cross-path
  transaction byte-equivalence.
- Native mobile scaffold (`mobile/`) — DEVELOPMENT status, honestly labeled.

### Changed
- `agent-sdk/` (v0.4.1's headless delegate helper) was superseded by the
  platform agent API + machine identities/capabilities.
- `tools/staging-acceptance.js` drives the staging deployment from the
  outside (static/security posture, real Schnorr auth, tenancy, caps,
  rate limits); `tools/prod-acceptance.js` is its network-aware
  production successor with a fail-closed identity gate (required
  expected network + buildId) and strictly read-only foreign-data
  isolation probes.
- VM covenant workspace (`tests/vm`) is now path-portable: the repo
  root is resolved workspace-relatively (`CARGO_MANIFEST_DIR`) instead
  of assuming a `~/policyvault` checkout, so `cargo test` passes from
  any clone location (the v0.4.1 tree hardcoded the path). The
  published suite is the production + adversarial + encoder/
  SDK-integration set; internal design-probe experiment tests are not
  published (their probe contracts under `contracts/experiments/` are
  intentionally excluded — see `PUBLIC_RELEASE_MANIFEST.md`).

### Fixed (found during internal production acceptance; each with
reproduce-first regression + sabotage-sensitivity suites)
- Manifest-record lifecycle: an identical-intent rebuild after a reject
  could silently bind to a stale record and fail only after the wallet
  signature; records are now content-addressed shared evidence with an
  explicit create/share/reuse classification and a content-bound finalize
  gate (`sdk/test/rc-lc1-*`).
- Risk workflow: a released review hold was unreachable for a solo
  operator; an id-less exact re-submission now consumes the released hold
  exactly once, restrictive-only (`sdk/test/rc-ux1-*`, `web/test/rc-ux1-*`).
- Governance lifecycle: a consumed proposal could later be relabeled
  cancelled; consumption is now terminal with a closed transition machine
  (`sdk/test/rc-gv1-*`).
- External-approver discovery (found in live production operation,
  2026-08-27; hotfix deployed and automated-accepted): hosted tenancy's
  participant derivation read the persisted-JSON field name
  (`approverSlots`) off the normalized in-memory manifest (field:
  `approvers`), so external covenant-approver keys never entered the
  participant set — an approver-only wallet could not see its vault, the
  open request, the request by id, or reach the approvals route (tenancy
  404 in front of the signature verifier). Strictly fail-closed
  availability defect: no funds, authority, or cross-tenant exposure;
  approval authority itself (slot-bound signature verification) was
  never affected. The fix reads the normalized field, and a new
  request-mutation guard pins reject/signature/submit/genesis-submit to
  signer/owner/agent/delegate principals so approvers gain exactly
  read + approve and nothing wider
  (`sdk/test/external-approver-discovery*.test.js`,
  `web/test/external-approver-inbox.test.js`).

### Security posture
- Internal hostile-AI adversarial review published
  (`docs/postlaunch/hostile-ai-review.md`) with its remediations and
  pinning suites (`security/hostile-ai/`).
- **No external professional audit has occurred** (planned; see SECURITY.md).

## v0.4.1 — Initial Mainnet Release (2026-08-23)

First public release: covenant v0.4.1 (fee reserve, multi-agent, Merkle
recipients, M-of-N approvals), Node SDK, self-hosted server + web client,
real-VM verification workspace, testnet drivers, protocol documentation.
