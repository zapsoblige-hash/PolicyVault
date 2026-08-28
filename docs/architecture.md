# PolicyVault Architecture

## Layers

```
                    ┌───────────────────────────────────┐
   web/ (dashboard) │  owner UI — read/status/audit only │
                    └───────────────┬───────────────────┘
                                    │ HTTP /api/v1
                    ┌───────────────▼───────────────────┐
   server/          │  backend API — registry, status,   │  NOT the
                    │  audit. No keys. No success without │  security
                    │  chain proof.                       │  boundary
                    └───────────────┬───────────────────┘
                                    │ require()
   sdk/  ┌─────────────────────────▼──────────────────────────┐
         │ amounts · vault-state · contract-compiler · manifest │
         │ chain · submission-claim · create/spend/lifecycle/   │
         │ recover · reconcile · audit · organization · keys    │
         └───────────┬───────────────────────────┬─────────────┘
                     │ silverc + pv_call_encoder  │ WASM RPC
         ┌───────────▼───────────┐    ┌───────────▼─────────────┐
         │ SilverScript compiler │    │ rusty-kaspa node (L1)   │  ← the
         │ (exact live state)    │    │ CONSENSUS = security     │  boundary
         └───────────────────────┘    └─────────────────────────┘
```

`agent-sdk/` sits beside `server/` as an alternate delegate-facing consumer of
the same SDK.

## The covenant and exact live state

`contracts/PolicyVault.v0.1.beta.sil` is a `#[covenant.singleton]` contract.
Immutable policy (owner, delegate, vaultId, caps, budget, period length,
recipients) rides in the constructor and becomes part of the compiled
**template**; mutable accounting (protectedValue, periodStartDaa, periodSpent,
paused) lives in the state region.

`contract-compiler.js` templates exact state values into the `.sil` source and
runs `silverc`, producing a per-state artifact under `data/build/<stateId>/`.
`state_layout` separates the state region from the template; the template hash
is the vault's policy identity, and the state ID is the app-level identity of
one exact live state.

## Transaction pipeline

`intent → build → sign → finalize → submit → reconcile`, with strict rules:

- Builders never broadcast; finalizers never mark chain state changed.
- A durable **transition claim** (keyed by the exact live outpoint) and a
  **submission claim** (keyed by txid) are written before broadcast, so a
  crash on either side of the RPC call is recoverable.
- Success requires chain proof: the old outpoint consumed, the expected
  successor observed with exact value and lineage covenant id, and a durable
  receipt persisted. Only then does the manifest advance.

## Covenant-call encoding

The covenant-call signature script is produced by `pv_call_encoder` (Rust,
`tests/vm/src/bin/`), which calls SilverScript's
`build_sig_script_for_covenant_decl`. The SDK appends the redeem-script push
(OpPushData2 + script). The encoder dispatches on an explicit
`contractVersion` (absent = v0.1; unknown values fail closed) because the
constructor-argument layout — including where the vaultId lives — differs
per contract version. Covenant inputs carry computeBudget 100 (v0.1) or 20
(v0.2, sized from measured script units with 6x headroom), sigOpCount 0
(Toccata tx version 1); ordinary fee inputs carry computeBudget 10.

**Production-byte rule:** every component that shapes consensus-visible
bytes (this encoder, the exact-state compiler, serializers, finalizers) has
an integration test that executes its exact output on the real VM
(`tests/vm/tests/v2_encoder_integration.rs`, `pv_replay_probe`,
`pv_compile_probe`); see `docs/v02-production-boundary-audit.md`.

## Period accounting (the consensus time primitive)

Rollover uses `require(tx.time >= periodStartDaa + k*periodLengthDaa)`, which
compiles to CLTV. Kaspa consensus only accepts a transaction whose lock time
(a DAA score below the lock-time threshold) has been reached, so a delegate
cannot fake an early period reset; under-claiming elapsed periods is
budget-conservative. No client clock is trusted. See
`docs/source-review-findings.md` §3.

## Durability

Manifests, claims, receipts, and audit events are written with
temp-file → fsync → atomic-install (rename, or link for create-only claims) →
directory fsync (`durable-json.js`). Data lives under `data/` (gitignored).

## Organization layer (off-chain application metadata)

Organizations, members, role labels, vault-to-organization assignments,
and user-defined groups are application metadata under `data/orgs/`
(same atomic `durable-json` writes, optimistic `version` concurrency —
competing writes get 409 VERSION_CONFLICT, never a silent lost update).
**Organization roles are application metadata. They do not grant or
modify Kaspa covenant authority** — the wallet-request pipeline
authorizes signers only against the covenant's owner/delegate
identities and never consults this layer. Member wallet addresses pass
through the shared address-identity boundary; corrupt metadata surfaces
as an operational error and degrades to Unassigned without ever hiding
a vault or blocking funds operations. Full model: `docs/organization-model.md`.

## v0.3 SDK construction layer (Phase 4H — offline, production-byte-proven)

The v0.3 covenant (Merkle recipient allowlist + M-of-N approvals) has a
dedicated offline construction layer under `sdk/src/*-v3.js`:

- `vault-state-v3` / `contract-compiler-v3` — strict normalization (exact
  10-slot approver layout, required policyNonce) + exact 24-field
  live-state compilation (silverc; script 28,483 B / state 528 B), with a
  quarantined recovery-mode parse for break-glass `ownerRecover` from
  malformed (e.g. hand-baked-genesis) states.
- `recipient-merkle-v3` — the one canonical tree/proof/verifier
  (leaf `sha256(0x50563301‖xonly)`, depth ≤ 16).
- `vault-transitions-v3` — canonical successor derivation per entrypoint;
  callers supply intent, never successor state.
- `compute-budget-v3` — central proven-safe committed-budget tiers
  (31 / 135 / 29 / 16), fee-neutral by measurement; never lowerable.
- `frozen-tx-v3` + `tests/vm/src/bin/pv_tx_probe` — the canonical frozen
  unsigned transaction; txId/sighash/approval verification come from REAL
  rusty-kaspa consensus code (no JS consensus crypto). For v1
  transactions the sighash and txId exclude signature scripts and compute
  budgets (source-checked), so collection order is free and the frozen
  txId equals the broadcast txId.
- `approval-package-v3` — freeze-before-collect approval packages: fixed
  65-byte SIG_HASH_ALL slots, authoritative per-approval verification,
  canonical placeholders, 650-byte blob only when complete, and a sha256
  package commitment (integrity only — never a signing digest).
- `vault-builders-v3` — deterministic offline genesis + all 11 entrypoint
  builders with exact fees from the real `pv_call_encoder`
  (length-stable placeholder encoding; drift fails closed).

Production-byte gate: `tests/vm/tests/v3_sdk_integration.rs` runs the
real SDK to build finalized vectors and executes every one on the real
TxScriptEngine against the production covenant under production sig-op
pricing with the SDK's own committed budgets. The later API/UI layers
consume these builders and never touch covenant byte internals.

## v0.4 (PRODUCTION-VM-PROVEN + PRODUCTION-BYTE-PROVEN at Checkpoint C — NOT live-testnet-verified)

v0.4 is the intended FINAL major consensus expansion (after it, prefer
SDK/API/UI features over covenant growth). It adds two features, each
VM-experiment-proven via isolated probes
(`contracts/experiments/V4FeeProbe.sil`, `V4AgentProbe.sil`;
`docs/v04-experiment-results.md`) — the production covenant `PolicyVault.v0.4.sil` now exists (generator
`tools/gen_v4.js`), driven through the real pv_call_encoder + VM:

1. **Covenant-controlled fee reserve (FR-1).** One covenant UTXO holds
   `protectedValue + feeReserve`. The covenant computes the EXACT network
   fee in-script from full input/output value introspection
   (`OpTxInputAmount`/`OpTxOutputAmount`) and bounds reserve consumption
   to `min(maxFeePerTx, actualFee)`, so the reserve can only ever become
   network fee — never a redirected payment and never principal. Enables
   autonomous agent spending without a human supplying fee UTXOs.

2. **Multiple independent delegates / AI agents (MD-3).** Each agent's
   FULL policy (key, caps, budget, per-agent period, recipient root,
   approval threshold) is one authenticated Merkle leaf committed by a
   single `agentRoot` state field; the leaf binds the key, so no agent
   can inherit another's authority. Per-agent accounting is advanced
   in-covenant by recomputing `agentRoot` in the same Merkle walk. One
   vault-global 10-slot approver set gates spends above each agent's own
   threshold (approval model D). For parallel high-throughput agents,
   MD-4 (a child vault per agent, grouped by off-chain organization
   metadata) remains the application-layer option — no new consensus.

The single v0.3 delegate + its policy fields move INTO the agent leaf, so
fixed covenant state shrinks even as capability grows. v0.3 remains the
current reference covenant, unchanged; v0.4 is additive and
version-dispatched (unknown versions fail closed). See
`docs/covenant-spec-v0.4.md`, `docs/v04-fee-reserve-design.md`,
`docs/v04-multi-delegate-design.md`, `docs/v04-approval-model.md`,
`docs/v04-security-review.md`.

The final PolicyVault is ONE universal application (navigation: Vaults /
Agents / Approvals / Organizations / Activity) where Personal / AI Agent /
Business are UX PRESETS over a single version-aware security engine —
never separate engines or apps.

## v0.4 application integration (Checkpoint G, 2026-08-19)

The v0.4 covenant is integrated into the server/API/dashboard/wallet
architecture additively and version-aware. Durable state is
`sdk/src/manifest-v4.js` (schema `policyvault-vault-manifest/v4`): the fixed
template + mutable covenant state + a durable AGENT REGISTRY (agent policies +
per-agent recipient sets). Because v0.4 places agent policy inside the
authenticated agent tree, the registry is the metadata needed to reconstruct
the canonical `agentRoot`; the loader recomputes it and REQUIRES equality with
the covenant state (fail closed otherwise). `sdk/src/wallet-requests-v4.js`
orchestrates the offline lifecycle (BUILD → approvals → sign → FINALIZE → VM
preflight → durable claims) reusing the frozen SDK builders and the
version-agnostic claim/manifest/address/signer infrastructure. `server/src/api.js`
dispatches `/wallet/v4/*` routes and presents v0.4 vaults (`presentVaultV4`).
`web/app-v4.js` is the v0.4 dashboard. The pipeline is OFFLINE: it ends at
production-covenant VM preflight (`pv_vm_preflight`) and does not broadcast;
the live-node broadcast/chain-proof/manifest-advance is Checkpoint H.
