# VM ↔ pre-sign parity invariant + generation-specific enforcement matrix

Authoritative, post-Wave-2 promotion-hardening (2026-09-04). Companion to
the per-generation `*-security-claims.md` records. Frozen covenant bytes are
never mutated by this document.

## 1. The standing invariant (permanent; also in CLAUDE.md)

> Every deterministic, signer-visible hostile condition that the covenant
> can reject and that is **knowable before signing** MUST also be rejected
> by the shared deterministic core / SDK **before signing**, unless an
> explicit documented reason establishes that the condition is inherently
> consensus-, chain-, or environment-dependent.

Do NOT mechanically require an SDK analogue for conditions that cannot
truthfully be known pre-sign (their truth depends on future/current chain
state unavailable to the deterministic pre-sign context — e.g. a
predecessor already spent, or a relative-age/sequence-lock threshold).
**Never weaken covenant enforcement to obtain parity — the SDK must rise to
the covenant, never the reverse.**

## 2. Motivating regression (Wave 2, HD ancestor budget)

The HD presentation layer correctly computed the ancestor-intersection
effective authority, but the BUILDER did not enforce it before signing: a
level-3 spend under an EXHAUSTED level-2 ancestor budget was signed by the
builder and then refused by consensus (`script ran, but verification
failed`, tx `fd6d1b46…`). The covenant backstop worked, but the deciding
(pre-sign) layer violated signer-visible parity. Fixed in Wave 2
(`verifySpendWithinEffectiveAuthority` now accounts every ancestor's period
budget; pinned `core/model/test/hd-leaf-ancestor-budget.test.js`). This
class of divergence is what the invariant and the regression gate (§6)
prevent recurring silently.

## 3. Enforcement-layer taxonomy (per invariant, per generation)

- **COVENANT** — enforced in-covenant (consensus rejects a violating spend
  regardless of the client).
- **SHARED-CORE-SDK** — enforced pre-sign by the shared deterministic core /
  SDK builder (refuses to assemble/sign a violating transaction).
- **CLIENT-SIGNER** — relied on the external signer / client to satisfy;
  NOT covenant-enforced.
- **SERVER-COORDINATION** — a hosted-layer coordination control (never
  covenant authority).
- **CHAIN-CONSENSUS** — enforced only by node/consensus state that is not
  fully knowable pre-sign (e.g. an already-spent predecessor, a
  relative-age lock).
- **NOT APPLICABLE** — the invariant does not exist for this generation.
- **NOT PROVEN** — not verified this session; treat as unproven, not as
  absent or present.

A cell may carry two layers (e.g. COVENANT + SHARED-CORE-SDK = the
pre-sign/consensus parity the invariant asks for).

## 4. Generation-specific enforcement matrix

Generations: v0.4.1 (KAS safe-payment, FROZEN), v0.5 (token controller,
FROZEN), v0.6 (atomic composability, FROZEN, FIXTURE), v0.7-root (org root,
FROZEN), v0.7-payment (rooted token, FROZEN), v0.7-kas (rooted KAS,
CANDIDATE), v0.7-HD (hierarchical delegation, CANDIDATE).

| invariant (pre-sign knowable?) | v0.4.1 | v0.5 | v0.6 | v0.7-root | v0.7-payment | v0.7-kas | v0.7-HD |
|---|---|---|---|---|---|---|---|
| per-spend cap `maxPerSpend` (yes) | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | N/A | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| period budget, own leaf (yes) | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | N/A | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| ancestor-budget intersection (yes) | N/A | N/A | N/A | N/A | N/A | N/A | COVENANT + SHARED-CORE-SDK (Wave-2 fix) |
| recipient allowlist Merkle proof (yes) | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | N/A | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| approver M-of-N signatures (yes) | COVENANT (A7 gate) + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT (owner M-of-N) + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| approver signature is SIGHASH_ALL (yes) | COVENANT (A7 gate) | COVENANT (A7 inherited) | COVENANT | COVENANT (owner sigs) | COVENANT | COVENANT | NOT PROVEN |
| **agent's OWN signature is SIGHASH_ALL** (yes) | **CLIENT-SIGNER** (NOT covenant — see §5) | NOT PROVEN | NOT PROVEN | N/A | NOT PROVEN | **COVENANT** (E6 hardening) | NOT PROVEN |
| **foreign / root-rider input closure** (yes) | **CLIENT-SIGNER / self-bound** (NOT covenant — see §5) | COVENANT (`requireNoForeignCovenantInputs`) | COVENANT | COVENANT (`requireOnlyRootCovenantInputs`) | COVENANT | **COVENANT** (E6) | COVENANT (inherits payment; NOT PROVEN independently) |
| successor / value conservation (yes) | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| root authorization present on owner op (yes) | N/A | N/A | N/A | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| KIP-9 storage-mass ≤ 500,000 g (yes, builder preflight) | CHAIN-CONSENSUS + SHARED-CORE-SDK (preflight) | +preflight | +preflight | +preflight | +preflight | +preflight | +preflight |
| stale / already-spent predecessor outpoint (NO — chain state) | CHAIN-CONSENSUS (+ SERVER-COORDINATION reconcile) | same | same | same | same | same | same |
| relative-age / sequence-lock delay (NO — chain DAA age) | N/A | N/A | N/A | CHAIN-CONSENSUS | N/A | N/A | N/A |

"+preflight" = CHAIN-CONSENSUS + SHARED-CORE-SDK (all builders wire
`sdk/src/storage-mass-preflight.js` over the corrected
`core/model/storage-mass.js`; fail-closed `STORAGE_MASS_OVER_LIMIT`).

## 5. v0.4.1 trust-boundary correction (Task 4; do not attribute v0.7-kas hardening to v0.4.1)

The FROZEN v0.4.1 covenant is NOT hardened the way the v0.7-kas CANDIDATE
is. Truthful distinctions (evidence: `docs/postlaunch/v0.7-kas-profile-readiness.md`
§0.1/§6; frozen `contracts/PolicyVault.v0.4.1.sil`):

- **Approver signatures ARE covenant-enforced on v0.4.1** — the A7 gate
  requires every counted approval to be a 65-byte signature ending in 0x01
  (SIG_HASH_ALL) before `checkSig` (`PolicyVault.v0.4.1.sil` lines 33–34,
  149–150).
- **The agent's OWN SIGHASH_ALL is NOT covenant-enforced on v0.4.1** — the
  agent's `checkSig(agentSig, agentPk)` carries no sighash-type gate. It is
  a CLIENT-SIGNER responsibility on v0.4.1. (v0.7-kas's E6 hardening ADDED
  the in-covenant gate; v0.4.1 was left frozen.)
- **The foreign / root-rider input closure is NOT covenant-enforced on
  v0.4.1** — `agentSpend` has no foreign-covenant-family check; it predates
  multi-family transactions. It is safe on v0.4.1 by SELF-BINDING (the
  fee/principal/successor rules bind via `OpAuthOutputIdx(activeInputIndex,
  0)` and do not depend on other inputs), NOT by input exclusion. v0.5+
  add `requireNoForeignCovenantInputs`; v0.7-kas adds
  `requireOnlyRootCovenantInputs`.
- Remaining v0.4.1 protection is supplied by exact
  successor/conservation/policy rules, which ARE covenant-enforced.

Do NOT describe the v0.4.1 agent-SIGHASH / input-closure scoping as an
exploit — no exploit is demonstrated; the spend rules are self-bound. Do
NOT claim a funded/nonterminal mainnet v0.4.1 vault exists without current
chain evidence. Frozen v0.4.1 bytes are never mutated; changing this
boundary would be a NEW additive generation, never an edit.

## 6. Standing SERVER-COORDINATION invariant — cryptographic state transitions (owner addendum §F, 2026-09-04)

> **No server-side state transition with cryptographic meaning may be driven
> by field presence alone. The cryptographic evidence must first be verified
> against the exact expected signer, key/slot, request domain, and commitment.**

Applies to every generation's hosted coordination layer (v0.4.1, v0.5, v0.6,
v0.7-root/payment/kas/HD): a request moves to SIGNED / a slot to SIGNED / a
succession to authorized only after the presented signature material has
executed on the real production VM (`pv_vm_preflight`, `sdk/src/vm-preflight.js`)
against the exact spent UTXO, expected key or owner slot, and the frozen
canonical transaction — never because `signedSafeJson`, `signatureHex` or a
slot response merely arrived. Motivating incident: rc11 internal security
review F-04 (a foreign caller drove an organizational-root genesis request to
SIGNED with a bogus 66-byte signature script; the verification happened only
at broadcast).

| condition | layer | negative test |
|---|---|---|
| bogus / wrong-key / truncated / replayed signature on a wallet-signed input (v5, v6, v7 root genesis, v7 wallet, HD) | SERVER-COORDINATION (VM preflight before SIGNED) + CHAIN-CONSENSUS | `sdk/test/cryptographic-transition-invariant.test.js` |
| v4 fuel / covenant inputs at finalize | SERVER-COORDINATION (`preflightAllInputs`) + CHAIN-CONSENSUS | same |
| org-root slot signature under the wrong slot key / wrong request domain / wrong commitment | SERVER-COORDINATION (`submitSlotSignature` verifies against the slot envelope) + COVENANT (SIGHASH_ALL owner quorum) | same (test 4) + `sdk/test/org-root-slot-signer-v7.test.js` |
| principal → signer binding on every hosted build; foreign mutation refused before any verification runs | SERVER-COORDINATION (tenancy) | `sdk/test/hosted-foreign-tenant-matrix.test.js`, `sdk/test/hosted-build-authority.test.js` |

This invariant is coordination hygiene, never covenant authority: the
covenant still refuses an unverified signature at consensus regardless of
what the server persisted.

## 7. Regression gate

`sdk/test/vm-presign-parity.test.js` (added this session) asserts, for each
generation with a delegated-spend builder, that a representative pre-sign-
knowable hostile condition (an over-cap spend) is REFUSED by the SHARED-CORE
transition layer BEFORE any signing (closed code, no transaction produced)
— i.e. pre-sign/covenant parity holds for the canonical case. It also pins
this matrix's "pre-sign knowable ⇒ SHARED-CORE-SDK refusal" contract so a
future hostile-matrix change cannot silently drop pre-sign enforcement
without breaking a test. The HD ancestor-budget case stays pinned in
`core/model/test/hd-leaf-ancestor-budget.test.js`.
