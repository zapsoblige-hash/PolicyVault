# VM ↔ pre-sign parity invariant + generation-specific enforcement matrix

Authoritative, post-Wave-2 promotion-hardening (2026-09-04). Companion to
the per-generation `*-security-claims.md` records. Frozen covenant bytes are
never mutated by this document.

**`fullscale-rc33` replacement addendum (2026-09-10):** the corrected browser genesis row (selected-root snapshot, independent template-pin reconstruction, recheck at signing) is carried by the replacement image and re-proven on its exact bytes (`web/test/kas-genesis-root-binding.test.js` and the substitution probe run inside the image, `docs/postlaunch/ux-evidence/claude-rc33/probes/`); the v0.4.1 submit-time creation recheck and the KAS observation-only genesis recovery are added to the matrix as `sdk/test/v4-genesis-creation-containment.test.js` and `sdk/test/v7-kas-genesis-observation-recovery.test.js` (both re-run in-image). Frozen covenant bytes unchanged; the KAS profile stays CANDIDATE with its freeze PROPOSED (`v0.7-kas-covenant-byte-freeze.md`).

**RC32 Codex addendum (2026-09-10):** the KAS predecessor/successor and pinned-recovery checks below passed independent adversarial/compiler verification. Original RC32's browser genesis row was incomplete: mutually consistent server root/template declarations were not bound to the selected root. The separate corrected source `c76d06488e7e88edbcc1a09bc860e437d030b8c2` snapshots that root, reconstructs its template pins independently, rechecks the current rules before the wallet, and binds asynchronous continuation to the active review. The original image is blocked and requires a replacement; this addendum does not relabel its bytes as corrected. See [independent review](v0.7-mainnet-enablement-codex-review.md).

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
| **predecessor / successor SCRIPT bound to the declared pins + reviewed states** (yes — the redeem is revealed pre-sign) | NOT PROVEN (no shared-core script reconstruction for this generation; the SDK compiles the exact successor itself) | NOT PROVEN for the controller's own successor script (the token-family template carriage IS bound: `verifyTokenInputRedeem`) | NOT PROVEN (same as v0.5) | COVENANT + SHARED-CORE-SDK (`rootScriptsBound`, root-script-v7 skeleton) | COVENANT + SHARED-CORE-SDK (vault-script-v7 skeleton: `templatePinsBound` / `successorScriptReconstructed` / `successorScriptFromPins`) | **COVENANT + SHARED-CORE-SDK** (R7-04 CLOSED 2026-09-10: vault-script-v7-kas CANDIDATE skeleton, same three checks + `vaultRedeemMatchesUtxo` / `vaultRedeemStateAgrees` / `vaultGenerationAgrees`, and `payoutToPinnedRecoveryPk` bound to the recovery key COMPILED INTO the spent script; RED-first `sdk/test/rooted-kas-hostile-matrix.test.js`, silverc matrix `sdk/test/vault-script-v7-kas-reconstruction.test.js`) | NOT PROVEN (candidate; no skeleton) |
| root authorization present on owner op (yes) | N/A | N/A | N/A | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK | COVENANT + SHARED-CORE-SDK |
| KIP-9 storage-mass ≤ 500,000 g (yes, builder preflight) | CHAIN-CONSENSUS + SHARED-CORE-SDK (preflight) | +preflight | +preflight | +preflight | +preflight | +preflight | +preflight |
| stale / already-spent predecessor outpoint (NO — chain state) | CHAIN-CONSENSUS (+ SERVER-COORDINATION reconcile) | same | same | same | same | same | same |
| relative-age / sequence-lock delay (NO — chain DAA age) | N/A | N/A | N/A | CHAIN-CONSENSUS | N/A | N/A | N/A |
| **BROWSER signing boundary: the wallet payload is the REVIEWED frozen transaction and a GENESIS output is the locking script REBUILT from the reviewed rules** (yes — every byte is known pre-sign) | BROWSER (`web/verify-intent.js` binds the v4 manifest to the exact unsigned Safe JSON; D2 mandatory binding in `walletSign`) | BROWSER (token manifest through the verify-intent router) | BROWSER (same router) | BROWSER (`web/org-root-ui.js`: `bindRootSigningPayload` / `signOwnSlot` — txid + frozen cross-check + root outpoint + terminal payout; root genesis SPK rebuilt via `core/intent/root-script-v7`) | BROWSER (same slot binding; rooted-vault genesis rides a root request) | **BROWSER (v0.7 enablement 2026-09-10, `web/kas-vault-ui.js`): genesis — output 0 MUST equal `reconstructVaultScriptSpkHexV7Kas(reviewed template + initial state)` (candidate skeleton, silverc-proven) after the server summary is cross-checked value for value; delegate payment / approver co-signature — `structuredSpend` VERIFIED_EXACT with the predecessor redeem bound (R7-04) + txid + frozen cross-check + signer role; owner ops — the KAS-family slot binding with terminal payout = ENTIRE balance; `web/test/kas-vault-ui.test.js` on production-byte fixtures** | NOT PROVEN (candidate; no browser surface) |

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
