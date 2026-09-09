# Walkthrough: the v0.7 organizational M-of-N owner root

**Status: TESTNET-VERIFIED CANDIDATE, byte-freeze decision pending
(owner-only). NOT in the hosted web app.** Nothing on this page is live
today. It describes a real, evidenced covenant candidate
(`docs/postlaunch/v0.7-organizational-root-design.md`, lane
`v07-org-root`) and the walkthrough its hosted UI will follow once that
surface is built and the covenant is byte-frozen. Read this as "what
comes next and what it will look like," not "what you can click on
right now."

## First: two different things share the word "organization"

PolicyVault's hosted app already has an **Organizations** tab today
(v0.4.1). That is a **HOSTED ORGANIZATION**: a server-side grouping of
vaults with member/role labels and an organization-scoped audit view.
It is application metadata. **It grants nobody covenant-level spending
or owner authority.** Every v0.4.1/v0.5/v0.6 vault still has exactly one
on-chain owner key, whether or not it's grouped into a hosted
organization — see `not-a-wallet.md`.

An **ON-CHAIN ORGANIZATIONAL ROOT** (v0.7) is different in kind: it is a
covenant where *ownership itself* is an M-of-N quorum of keys, enforced
by Kaspa consensus, exactly the way a single owner key is enforced
today. A hosted organization with v0.7 rooted vaults underneath it is
the first PolicyVault configuration where the grouping UI's implied
multi-person control is also true on-chain. Until v0.7 ships as a
product, treat every "organization" as hosted-only — it does not upgrade
a vault's owner-key security.

## The architecture (candidate, testnet-verified)

One shared `PolicyVaultOrgRoot` covenant plus rooted profile successors
(the first rooted profile derives from the frozen v0.5 token/payment
covenant by 13 exact-match edits, fail-closed on any drift). Candidate
identities: `PolicyVault.v0.7-root.sil` sha256 `69417514…` and
`PolicyVault.v0.7-payment.sil` sha256 `09cdbb6c…` — candidates, not
frozen; the owner byte-freeze decision has not been made.

## Walkthrough: creating an organizational root

Every step below is a **DESIGN TARGET**, engine-proven on the VM and
live on testnet-10, not yet exposed by any UI.

1. **CREATE ORGANIZATION ROOT.** Choose the root's owner slots — the
   keys that collectively constitute ownership. The candidate's
   consensus sig-op budget (≤ 15 static) bounds practical N; every
   counted owner signature is `SIGHASH_ALL`-gated in-covenant.
2. **Set the M-of-N quorum** for ordinary root actions (expanding
   authority, rotating keys, approving a rooted vault's policy changes).
3. **Set the emergency FREEZE quorum K.** Freeze is a monotonic
   authority-*reducing* action, so it deliberately gets a lighter rule
   than M-of-N (a smaller K can pause the root without waiting for full
   quorum) — you cannot do more harm by pausing.
4. **Set the recovery quorum R and its delay.** Recovery is a
   break-glass path: it requires R owner signatures and cannot execute
   until an idle delay has passed (consensus-enforced via
   `check_sequence_lock` — proven, both directions, on real testnet-10
   transactions: rejected at age 49/47, accepted at age 636/624).
5. **Set the succession authority and its delay.** Succession changes
   who the primary key is (design rule D1); like recovery, it is
   delay-gated.
6. **Review the exact root policy** — the same "frozen bytes, human
   review before signature" discipline as every other PolicyVault
   transaction (`not-a-wallet.md`).
7. **Collect independent owner signatures** — each owner slot signs
   separately; there is no single key that can act alone once the root
   is real.
8. **Verify** the fully-signed transaction against the frozen bytes
   reviewed in step 6, **broadcast**, **reconcile** against the observed
   chain successor, and record a **policy-execution attestation** (see
   `docs/postlaunch/execution-attestation-spec.md` and
   `adoption-metrics-spec.md`'s neighbor concept, not the same thing).

## Walkthrough: creating a rooted vault

9. **CREATE ROOTED VAULT**, binding it to the exact organizational root
   from step 1–8 (the vault's covenant carries the root's identity; a
   vault cannot be silently re-parented to a different root).
10. **Set the vault's own profile policy** — the ordinary per-agent
    caps, budgets, and recipient allowlist you already know from
    `quickstart-kas-delegated-payment.md`. The root does not replace
    that policy; it replaces the single owner key that ultimately
    controls it.
11. **Fund** the vault.
12. **Operate**: delegated spends proceed exactly as in v0.4.1/v0.5 —
    day-to-day agent activity does not require quorum. Quorum authority
    only engages for root-level actions (expansion, freeze, recovery,
    succession) — evidenced testnet delegate spend under a rooted
    profile costs +363 B / roughly +3.0% versus an unrooted v0.5 spend.

## The outcome ladder (never treat "pending" as success)

Every root and vault action above moves through the same durable ladder
PolicyVault uses everywhere funds are involved:

```
AUTHORIZED → SIGNED → BROADCAST → CHAIN_SEEN → CHAIN_VERIFIED → VERIFIED_OUTCOME
```

`submitTransaction` returning is never treated as success. A durable
receipt only advances past `CHAIN_VERIFIED` once the expected successor
state is actually observed on-chain; `VERIFIED_OUTCOME` is the terminal,
independently-checkable record. See
`docs/postlaunch/execution-attestation-spec.md` for the canonical
machine-verifiable record and independent verifier this ladder feeds.

## Dangerous actions — read this before you click anything, once this ships

- **Recovery** and **succession** are delay-gated (steps 4–5) and — by
  design rule D6 — **land the vault/root FROZEN**, not immediately back
  in normal operation. A quorum has to deliberately unfreeze afterward.
  This is intentional: it stops a successful-but-surprising recovery or
  succession event from silently resuming agent spending before the
  remaining owners have confirmed the new state is what they intended.
- **Rotation** (replacing an owner slot's key) and **unfreeze** are
  quorum-gated M-of-N actions, not single-signature actions.
- None of these actions can be performed, delayed, or bypassed by
  PolicyVault's servers — the delay and quorum are enforced by the
  covenant, verified against consensus (`check_sequence_lock`), exactly
  like every other rule in this document. See `not-a-wallet.md`.

## Evidence, honestly

- **DESIGNED · PROBED (×2 real-engine probes) · IMPLEMENTED (candidate)
  · VM-VERIFIED · SDK/PRODUCTION-BYTE-VERIFIED · EXPLAINED ·
  SIGNER-PATH-TESTED · FEE-MODELED · TESTNET-VERIFIED** →
  `V0.7-ORGANIZATIONAL-ROOT-TESTNET-VERIFIED-BYTE-FREEZE-READY`.
- Live testnet-10 lifecycle: 19/19 chain-verified transitions across
  three owner-set generations (genesis → delegated spend →
  root-governed expansion → emergency pause via FREEZE K=1 → unfreeze →
  rotate → threshold 2→3 → freeze/unfreeze → owner-recovery after the
  idle delay → succession after its delay → terminal recover to the
  genesis-pinned cold key); 9/9 authorized negative-validation
  rejections; coordinator node readback agrees.
- **NOT byte-frozen** — the freeze decision is a later, deliberate owner
  decision, never inferred from readiness.
- **NOT in the hosted web app, SDK public surface, or MCP tool catalog**
  yet — this worktree does not even carry the design document or
  covenant source (they live on the separate `v07-org-root` lane); this
  page was written from the durable burn-down record
  (`docs/postlaunch/flagship-readiness-matrix.md` row C,
  `docs/postlaunch/flagship-development-program.md` track 3), not from
  reading that lane's source directly.

Source: `docs/postlaunch/flagship-readiness-matrix.md` (row C),
`docs/postlaunch/flagship-development-program.md` (§1, track 3).
