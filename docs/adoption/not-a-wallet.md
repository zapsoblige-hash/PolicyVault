# PolicyVault is not a wallet

PolicyVault never holds a private key capable of moving funds. It does
not sign, and it does not custody. Every signature that can move KAS
comes from a signer the owner or delegate controls (a browser wallet
extension, a hardware/air-gapped signer, or an external key management
system) — never from PolicyVault's servers, its SDK, or its API.

## The authority statement

> **AI MAY REQUEST.**
> **POLICYVAULT DETERMINISTICALLY DECIDES.**
> **THE COVENANT ENFORCES.**
> **SIGNERS RETAIN CUSTODY.**

Each line is a distinct actor with a distinct, narrow job:

- **AI MAY REQUEST** — an AI agent, a script, or a person can *ask* for a
  spend, a pause, a top-up. A request is only ever a proposal.
- **POLICYVAULT DETERMINISTICALLY DECIDES** — the application (server,
  SDK, or browser) evaluates the request against the vault's policy and
  builds the exact transaction bytes that would carry it out — or
  refuses, with a specific reason. This decision is a convenience: it
  saves everyone from hand-encoding a covenant call, and it is what
  produces the human-readable review the signer sees. It is **not** the
  security boundary.
- **THE COVENANT ENFORCES** — the SilverScript covenant compiled into
  the vault's own Kaspa script is what actually stops an out-of-policy
  transaction from confirming. Kaspa consensus verifies the covenant on
  every spend; a delegate holding the legitimate key who bypasses
  PolicyVault entirely and submits a hand-built transaction straight to
  a node is still bound by it.
- **SIGNERS RETAIN CUSTODY** — the owner's key, the delegate's key, and
  any approver's key never leave the signer that holds them. PolicyVault
  never sees, requests, or stores a seed phrase or private key.

## The architecture

```
                     ┌───────────────────────────┐
   AI / app / person │        REQUEST ONLY        │  "spend 4 KAS to X"
   ─────────────────▶│   (never itself authority) │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │   PolicyVault (server /    │  builds the EXACT
                     │   SDK / browser)            │  transaction bytes,
                     │   DETERMINISTIC DECISION    │  or a specific refusal
                     │   — a convenience layer,    │  code — never signs,
                     │   NOT the security boundary │  never broadcasts
                     └─────────────┬─────────────┘
                                   │  frozen, reviewable
                                   │  transaction bytes
                                   ▼
                     ┌───────────────────────────┐
   external signer   │   SIGNER (wallet / CLI /   │  the human or delegate
   ─────────────────▶│   air-gapped device)        │  reviews the bytes and
   holds the key      │   CUSTODY STAYS HERE       │  signs, or refuses
                     └─────────────┬─────────────┘
                                   │  signed transaction
                                   ▼
                     ┌───────────────────────────┐
                     │   Kaspa L1 covenant        │  verifies cap, budget,
                     │   (SilverScript, on-chain) │  allowlist, owner/agent
                     │   THE COVENANT ENFORCES    │  identity, successor
                     │   — the actual security    │  state — in CONSENSUS,
                     │   boundary                 │  independent of every
                     └───────────────────────────┘  layer above it
```

Nothing above the bottom box is trusted with funds. A compromised
PolicyVault server can mislead, hide information, or ask a signer to
approve a *policy-valid* transaction the human didn't intend — it cannot
produce a signature, and it cannot make the covenant accept a
policy-invalid one. See `SECURITY.md` for the exact compromised-component
model and what each layer can and cannot do.

## Owner recovery is terminal, not a backdoor

The owner can always recover 100% of a vault's funds to their own key —
this is a safety valve, not custody by PolicyVault. It is:

- **owner-only** (requires the owner's signature, enforced by the
  covenant, not by PolicyVault's application logic);
- **terminal** (the vault's covenant state ends; funds land at a plain
  owner-controlled output, not a new covenant instance);
- **not a master key.** PolicyVault holds no key that can perform
  recovery, pause, or any other owner action on the owner's behalf. If
  the owner's key is lost, PolicyVault cannot recover the vault — there
  is no custodial recovery path. Back up the owner key.

## What is, and is not, enforced on-chain

**On-chain (Kaspa consensus):** delegate identity, owner identity,
per-spend cap, cumulative period budget, consensus-verifiable period
progression, recipient allowlist, exact payment value, value
conservation, exact successor state, vault-identity continuity, pause,
owner recovery.

**Off-chain (application data, never enforced by consensus):**
organization/member/role labels, vault names and grouping, dashboards,
audit-log presentation. These can never move or authorize KAS — an
"organization" in PolicyVault today is a label for grouping vaults, not
a covenant-level multi-owner authority. See
`organizational-root-walkthrough.md` for the distinction between that
hosted grouping feature and the v0.7 on-chain organizational root.

## See also

- `SECURITY.md` — the full compromised-component model and the
  production-byte integration rule.
- `developer-integration-example.md` — a runnable example that proves
  the covenant's recipient-allowlist enforcement mechanically, offline.
- `docs/threat-model.md`, `docs/security-invariants.md` — the underlying
  invariant and attack-matrix documents this file summarizes for a first
  reader.
