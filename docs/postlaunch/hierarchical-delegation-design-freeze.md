# HIERARCHICAL DELEGATION — DESIGN FREEZE (owner-accepted 2026-09-03, Flagship Wave 2 §0)

**Verdict: HIERARCHICAL-DELEGATION-DESIGN-FROZEN.** This freezes the DESIGN
recorded in `docs/postlaunch/hierarchical-delegation-design.md` (§0–§6, incl.
the probe results) and the probe evidence it rests on. It freezes **no
production covenant bytes**: the experimental probe covenant is not a product,
and the production successor built under Track D of this wave is a NEW
candidate that must reproduce every property below on the real engine, in
composition with the rooted (v0.7) vault, before it can be considered for its
own byte freeze (a later, separate owner decision).

Authorization (owner directive, Wave 2 §0, verbatim intent): *"I ALSO ACCEPT
the hierarchical-delegation DESIGN FREEZE, subject to exact re-verification of
the recorded probe evidence and limits. Freeze the design, NOT production
covenant bytes."*

## 1. Frozen identities (re-verified by the coordinator before recording)

| item | identity |
|---|---|
| design record `docs/postlaunch/hierarchical-delegation-design.md` | sha256 `e23b860eaa296dd890b8c23e299bd631e7740274508ddaca8dc57dc24cf4e128` (lane `hd-design` tip `2fc673b`) |
| experimental probe covenant `contracts/experiments/HDProbe.sil` (NOT a product; measurement + falsification artefact) | sha256 `dbee385d117beb5ec4de5f29dbc9e19873663f8e0599625b40a59b57cf9c246d` |
| real-engine probe suite `tests/vm/tests/hd_experiment.rs` | sha256 `78d4b5944d663f33149e21be4c83ac54804d7494d20cc4c2a4c0e57d78b88c89` |
| baseline the probe was derived from | frozen `contracts/PolicyVault.v0.5.sil` sha256 `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9` — UNCHANGED before and after the probe wave and at this record |
| coordinator re-verification (fresh, mechanical) | `cargo test --test hd_experiment` on lane `hd-design` `2fc673b`: **14 passed / 0 failed** (231.95 s; real TxScriptEngine, rusty-kaspa v2.0.1, real Schnorr) — reproduces the worker's 14/14 and the wave-1 coordinator re-run (237 s) |

## 2. Binding design rules (owner, Wave 2 §0 — verbatim intent; each mapped to its evidence)

| rule | frozen meaning | evidence in the design record |
|---|---|---|
| **Authority may NEVER increase descending.** | every descendant's effective authority is bounded by the per-spend INTERSECTION against EVERY ancestor (caps, period budgets with each level's own counter, recipient allowlists by k membership proofs, fee/carry caps, swap permissions) — never trusted at delegation time | §1.3; §6.7 (66 hostile rows, 0 accepted); §6.8 (guards proven load-bearing by sabotage) |
| **MAX_LEVEL = 3 is an implementation constraint derived from measured stack limits, not a marketing/configuration choice.** | `MAX_STACK_SIZE = 244` (`~/rusty-kaspa/crypto/txscript/src/lib.rs`) binds the depth: level-3 spend peaks at 208 items (36 headroom, depth-independent) with ONE 160-byte canonical body per ancestor; a level-4 spend extrapolates to 254 (OVER). A deeper tree requires a NEW measured design, never a configuration flag | §6.2, §6.5, §6.9 |
| **Every ancestor policy participates in the effective intersection.** | k membership proofs + k counter advances in one nested refold; a child cannot outrun a parent budget because the parent counter also advances; siblings share the parent budget | §1.3 items 1–6; §6.6 rows 2, 3, 7 |
| **Removing a parent removes its subtree authority.** | structural revocation: a removed/zeroed `childRoot` makes every descendant fail membership under the current roots | §1.2, §1.5; §6.6 row 6; §6.7 "Membership / structural revocation" |
| **Stale child proofs fail closed.** | membership is proven under the CURRENT `agentRoot` and CURRENT `childRoot`s (which are inside the current parent leaves); stale counters, re-policied parents and revoked children all fail membership; SIGHASH_ALL over the whole transaction | §1.5; §6.7 "stale parent leaf", "removed grandparent" |
| **`expiryDaa` is NOT a consensus upper-bound expiry; never claim otherwise.** | Kaspa `lockTime` is a LOWER bound only (`OpCheckLockTimeVerify`, `check_tx_is_finalized`); expiry is a consistency rule (`expiry(child) ≤ expiry(parent)`) + a shared-core/manifest refusal + revocation + periodic-budget decay. Every manifest/UI must say so | §0 row 1; §1.4; §6.10 |
| **No owner entrypoint may treat a delegate leaf as owner authority.** | owner/root operations require the owner signature (v0.5/v0.6) or the org-root input (v0.7); a leaf key is never an owner; distinct HD leaf domain tag (`0x50564801`, 173-byte preimage) separates HD leaves from every other PolicyVault leaf both ways | §1.1; §6.1; §6.7 "Leaf-domain separation, both directions", "Level / chain shape" |
| **v0.7 composition must be measured/proven rather than assumed.** | the probe composed with FROZEN v0.5 only; the 36-item level-3 headroom is the budget a rooted (v0.7) composition must FIT — measure it; if MAX_LEVEL 3 cannot fit with adequate stack, mass, standardness and adversarial headroom, STOP and report the maximum PROVEN rooted level; NEVER weaken the ancestor-policy intersection to preserve depth | §6.9 (OQ-HD-2), §6.10; this record §4 |

Also frozen from the probe: delegation requires `paused == 0` (OQ-HD-3, §6.9) and MUST also respect a FROZEN organizational root when composed with v0.7; in-state nested child roots (signature-chain certificates rejected for v1, §2); ONE parent signature can only NAME a key, never create authority (§1.2); position-derived `level` constants per entrypoint (§6.2); separate entrypoints per level pin their own chain length (§6.4 standardness note: 3/5/7 static sig-ops at MAX_LEVEL 1/2/3, all ≤ 15).

## 3. What the design freeze does NOT do

- It does not freeze any covenant bytes. `HDProbe.sil` remains an experiment
  (measurement + falsification artefact) and is never deployed, never given a
  production encoder arm as a product, never treated as an acceptance.
- It does not authorize production or mainnet use of hierarchical delegation
  in this wave (owner directive §5: "No production/mainnet use in this wave").
- It does not decide OQ-HD-1 (a cheaper stateless-child tier); §6.9 records it
  as open and, on the measurements, not worth adding.

## 4. Implementation contract for the production successor (Track D, this wave)

The successor follows the v0.5/v0.6/v0.7 discipline — I1 production
covenant/generator + real-engine VM; I2 shared core / SDK / manifest /
production-byte vectors; I3 hostile/adversarial + signer-visible presentation;
I4 fee/mass/standardness/stack measurements; I5 live testnet-10 lifecycle +
negative proof; I6 readiness synthesis — and it MUST compose with the rooted
(v0.7) vault architecture: the HD leaf tree lives under the rooted vault's
`agentRoot`, owner operations still require the organizational-root input with
byte-level successor pinning, and the FROZEN root state must refuse delegation
operations exactly as `paused` does. The successor is a NEW candidate
covenant/generator (never an edit of frozen v0.5/v0.6 or of the v0.7
candidates); its readiness record must state the MAXIMUM PROVEN ROOTED LEVEL
from measurement and every item of the owner's hostile test list (child over
parent cap; child over ancestor period budget; sibling budget interaction;
narrower child allowlist; broader forged child allowlist; stale parent proof;
removed parent; child-root substitution; level confusion; domain-tag
confusion; descendant attempting an owner operation; descendant attempting a
root operation; paused parent; revoked subtree; malformed body; altered nested
refold; budget rollover at multiple levels; SIGHASH variants; post-sign
mutation; fee-domain abuse; token-domain abuse; v0.5/v0.6/v0.7 cross-family
substitution) as a real-engine refusal.

## 5. Mechanical guard

`sdk/test/hd-design-freeze.test.js` pins the three identities in §1 and the
v0.5 baseline; any drift of the design record, the probe covenant or the probe
suite fails the SDK suite. Revising the frozen design is a NEW design record
(additive), never an in-place edit.
