# Changelog

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
