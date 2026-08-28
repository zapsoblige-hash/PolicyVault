# PolicyVault Transaction Intent Manifest — Specification v1

**Status: DESIGNED + IMPLEMENTED + UNIT-TESTED** (post-launch upgrade
program A). Implementation: `core/intent/` (pure CommonJS, zero external
dependencies, no server/SDK imports). Test suites:
`core/intent/test/` (`node --test`), 75/75 passing at the time of this
writing. This component is NOT VM-verified and NOT testnet-verified;
nothing here changes consensus-visible bytes, covenant behavior, or any
existing production file.

---

## 1. Purpose

A **Transaction Intent Manifest** is a deterministic, portable JSON
document that describes what ONE proposed PolicyVault transaction
ACTUALLY does — identity, decoded transaction facts, exact sompi
accounting, state before/after, limit consumption, approvals, recipient
authorization, and the explicit policy-mutation diff — verified
fail-closed against the structured **requested intent** and the
structured **decoded transaction**, so that the claim

> **THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.**

is only ever emitted when it has been deterministically proven by the
complete detector catalogue (§7). Anything unknown, missing, ambiguous,
or unexplained refuses. There is no partial verdict and no default
route.

The manifest is the reviewable, hashable, transportable artifact that a
wallet UI, an approver, an auditor, an AI agent runtime, or a CLI can
independently re-verify before (and after) a signature is produced.

## 2. Architecture context

Four layers, four distinct responsibilities:

1. **Kaspa covenant (consensus)** — the hard financial authority
   boundary. Every rule that matters against a malicious actor holding
   a legitimate key is enforced here, on-chain, or it is not enforced at
   all. The manifest never substitutes for covenant enforcement; it
   *describes and cross-checks* what the covenant will be asked to
   accept.
2. **Portable shared core (`core/intent/`)** — the deterministic local
   security engine. Pure CommonJS, zero dependencies, no I/O, no
   network, no SDK/server imports; the only Node builtin is
   `node:crypto` sha256, isolated behind one function for future
   WebCrypto substitution. Designed to run identically in browser,
   mobile, CLI, and server contexts.
3. **Hosted layer** — coordination only (build, persist, collect,
   broadcast, reconcile). Per the hosted threat model, a compromised
   host must never gain unilateral authority over vault funds; a
   manifest lets every OTHER party re-derive the truth about a proposed
   transaction without trusting the host's prose.
4. **External signer (wallet)** — key custody. Signatures are produced
   in the user's wallet over frozen transaction bytes. The manifest
   gives the signing human/agent an exact, machine-verified statement of
   what those bytes do.

### 2.1 What v1 deliberately does NOT re-implement

Consistent with the standing project rule that consensus hashing is
never reimplemented in JS (`sdk/src/frozen-tx-v3.js` delegates txId /
sighash to real rusty-kaspa code via `pv_tx_probe`), manifest v1 **pins
and cross-checks** — but does not recompute — the outputs of the
consensus-backed layers:

- transaction id / sighash computation (rusty-kaspa via the SDK);
- Schnorr signature verification;
- Merkle fold recomputation (agent registry root, recipient allowlist
  membership) — the manifest records the roots and the SDK-proven
  membership verdicts (`allowlist.recipientAllowlisted`,
  `proofSupplied`) and verifies their *consistency* with the agent
  policy;
- covenant script compilation and VM execution (the existing production
  preflight).

What v1 DOES prove deterministically, with zero trust in the builder:
the complete sompi ledger, the per-action transaction shape, every
output's script-level destination, the exact state-transition equations
(the frozen v0.4 per-entrypoint field-preservation matrix and policy
nonce rule), agent limit arithmetic, the CLTV rollover lockTime rule,
and the binding of all of it to the requested intent. A manifest that
verifies plus a covenant preflight that passes together close the loop:
the described meaning is the requested meaning, and the bytes execute.

## 3. Encodings (normative)

- **Amounts / DAA scores / nonces / counters** — canonical base-10
  digit strings: `"0"` or `[1-9][0-9]*`. No signs, no decimals, no
  exponents, no whitespace, no leading zeros, ASCII digits only. Parsed
  to BigInt; bounded by `MAX_SOMPI = 29_000_000_000 × 10^8` unless a
  tighter bound applies. JS numbers are refused on every amount path
  (this is STRICTER than `sdk/src/amounts.js parseSompi`, which accepts
  leading zeros: one value must have exactly one encoding, because the
  manifest hash is a function of encodings).
- **Structural integers** (input/output indexes, `computeBudget` ≤
  0xffff, script version ≤ 0xffff, outpoint index ≤ 0xffffffff) — JS
  safe integers, mirroring `frozen-tx-v3.js`.
- **Hashes / x-only pubkeys / ids** — exact-width **lowercase** hex
  (32-byte fields are 64 hex chars). Uppercase refuses.
- **Scripts** — non-empty even-length lowercase hex. The standard P2PK
  script for an x-only key is `20 <32-byte key> ac` (OP_DATA_32 key
  OP_CHECKSIG), mirroring the SDK's `p2pkScriptHex`.
- **Booleans / null** — JSON literals. `undefined` anywhere is a
  refusal (a field may not be silently omitted).
- Every object schema is **CLOSED**: unknown keys refuse
  (`SCHEMA_INVALID`). A hidden field is a hidden effect.
- There are **no timestamps** in the manifest: identical transaction
  facts must produce the identical manifest hash on any machine at any
  time. Time metadata belongs to the surrounding request record (the
  durable wallet-request store), never to the manifest.

## 4. Versioning (fail closed)

| Identifier | Value |
|---|---|
| Manifest version | `policyvault-intent-manifest/1` |
| Requested-intent version | `policyvault-requested-intent/1` |
| Supported covenant versions | `policyvault-0.4`, `policyvault-0.4.1` |
| Hash domain | `policyvault-intent-manifest-hash/1\n` |

Rules:

- An unknown `manifestVersion` refuses with `UNKNOWN_MANIFEST_VERSION`
  **before any structural assumption is applied**. Never route an
  unknown version to a default.
- An unknown `intentVersion` refuses with `UNKNOWN_INTENT_VERSION`.
- A covenant version outside the supported list refuses with
  `UNSUPPORTED_COVENANT_VERSION`. This covers both unknown versions and
  versions manifest v1 simply does not describe (`policyvault-0.3` is a
  real frozen covenant, but v1 implements only the v0.4-family action
  set that production runs; claiming to verify a family without its
  detectors would be a false verdict). A future manifest version
  extends coverage **additively**, with its own version string and its
  own hash domain — v1 documents are never reinterpreted.
- An action outside the table in §6 refuses with `UNKNOWN_ACTION`.

## 5. The manifest hash (deterministic, representation-independent)

```
manifestHash = sha256_hex( "policyvault-intent-manifest-hash/1\n"
                           + canonicalJsonStringify(body) )
```

where `body` is the manifest document with the `manifestHash` key
removed, and `canonicalJsonStringify` (in `core/intent/canonical.js`)
mirrors the semantics of `sdk/src/canonical-json.js` exactly:

- arrays keep element order (order is consensus-meaningful: inputs,
  outputs, approver slots);
- object keys serialize in lexicographic UTF-16 code-unit order;
- primitives serialize exactly as `JSON.stringify`;
- `undefined`, functions, symbols, BigInt, non-finite numbers, and
  non-plain objects (Date, Map, class instances) FAIL CLOSED.

Motivation (real production incident, Phase G defect G-2): PostgreSQL
jsonb canonicalizes object key order, so a key-order-sensitive preimage
"mutates" across a storage round trip with every value byte-intact. The
manifest hash is therefore a function of VALUES only. The domain prefix
keeps intent-manifest hashes disjoint from every other
sha256(canonical-json) commitment in the codebase (approval-package
commitments, frozen-tx commitments, state IDs).

Regression tests prove: reordered-key rebuilds and JSON round trips hash
identically; every semantic change (amount, recipient, fee, state
field, array order, added key) changes the hash.

The hash proves **integrity** (the document was not altered after
build), never **honesty** — an adversarial author controls their own
hash. Honesty is what the detector catalogue (§7) proves.

## 6. Schema

### 6.1 Actions

Mirrors `ROLE_BY_ACTION` (`sdk/src/wallet-requests-v4.js`), the
per-entrypoint mutable-field matrix and the exact policyNonce rule
(`sdk/src/vault-transitions-v4.js`), plus genesis:

| sdkAction | role | genesis | terminal | may change (state fields) | policyNonce |
|---|---|---|---|---|---|
| `agentSpend` | agent | no | no | protectedValue, feeReserve, agentRoot | preserve |
| `ownerSetAgentRoot` | owner | no | no | agentRoot | +1 |
| `ownerSetApprovers` | owner | no | no | approverSlots, approvalM | +1 |
| `ownerTopUp` | owner | no | no | protectedValue (up) | preserve |
| `ownerTopUpReserve` | owner | no | no | feeReserve (up) | preserve |
| `ownerPause` | owner | no | no | paused (0→1) | preserve |
| `ownerUnpause` | owner | no | no | paused (1→0) | preserve |
| `ownerRecover` | owner | no | **yes** | — (no successor) | — |
| `createVault` | owner | **yes** | no | — (no predecessor) | — |

High-level owner lifecycle actions `addAgent` / `removeAgent` /
`rotateAgent` / `rePolicyAgent` map to `ownerSetAgentRoot` (exactly as
`planV4` does); the manifest records both (`action.sdkAction` +
`action.highLevelAction`), and the requested intent must still pin the
RESOLVED `newAgentRoot` — the requested-vs-built binding is on the
exact root commitment.

### 6.2 Requested intent (`policyvault-requested-intent/1`)

```
{
  intentVersion:   "policyvault-requested-intent/1",
  networkId:       string (^[a-z0-9][a-z0-9-]{0,63}$; e.g. "mainnet", "testnet-10"),
  vaultId:         hex32,
  covenantVersion: supported covenant version,
  action:          sdkAction or high-level action name,
  params:          per-action closed object (below),
  maxFeeSompi:     digits > 0 | null      // fee ceiling for this request
}
```

Per-action `params` (closed; every quantity canonical digits; every key
32-byte lowercase hex):

- `agentSpend` — `{ agentPk, recipient, payAmountSompi (>0),
  periodsElapsed (0..1000), reserveConsumedSompi }`
- `ownerSetAgentRoot` (and the four high-level names) —
  `{ newAgentRoot }`
- `ownerSetApprovers` — `{ newApproverSlots: exact 10-slot layout
  (sentinel = 64 zero hex), newApprovalM (0..10) }`
- `ownerTopUp` — `{ topUpAmountSompi (>0) }`
- `ownerTopUpReserve` — `{ topUpReserveAmountSompi (>0) }`
- `ownerPause` / `ownerUnpause` / `ownerRecover` — `{}`
- `createVault` — `{ owner, initialState: state tuple (§6.4, policyNonce
  "0", paused "0"), agentFuel: { xOnly, amountSompi (>0) } | null }`

### 6.3 Manifest top level (closed key set)

```
{
  manifestVersion, network, vault, action, actor, requested,
  transaction, effects, stateBefore, stateAfter, accounting,
  payment, allowlist, approvals, limits, policyMutations,
  warnings, unexpectedEffects, manifestHash
}
```

| Field | Shape | Notes |
|---|---|---|
| `network` | `{ networkId }` | must equal `requested.networkId` |
| `vault` | `{ vaultId, owner, covenantVersion, covenantId }` (all hex32 except the version) | owner is the template-immutable x-only key; covenantId is the genesis covenant lineage id |
| `action` | `{ sdkAction, highLevelAction\|null, role, genesis, terminal, aboveThreshold }` | role/genesis/terminal must equal the §6.1 table; `aboveThreshold` true only for `agentSpend` |
| `actor` | `{ role, signerXOnly, agentPk\|null }` | canonical identity is the x-only pubkey, never an address; owner ops require `signerXOnly == vault.owner`; `agentSpend` requires `agentPk == signerXOnly` |
| `requested` | the full intent document (§6.2) | embedded so the manifest is self-contained and the hash binds intent to transaction |
| `transaction` | §6.5 | the decoded FROZEN (unsigned) transaction |
| `effects` | `{ inputs: [{index, kind}], outputs: [{index, kind}] }` | one entry per tx input/output, in order; input kinds `covenant\|external`, output kinds `successor\|payment\|change\|recoverPayout\|genesisVault\|agentFuel`; covenant-bearing consistency is structural (§6.5) |
| `stateBefore` | `{ outpoint {transactionId, index}, stateId (hex32), state (§6.4) } \| null` | null iff genesis |
| `stateAfter` | `{ stateId, state, expectedOutpoint {transactionId, index} } \| null` | null iff terminal; `expectedOutpoint` names THIS transaction's covenant-bound output |
| `accounting` | §6.6 | the exact 11 builder fields |
| `payment` | `{ recipientXOnly, amountSompi (>0), outputIndex } \| null` | non-null iff `agentSpend` |
| `allowlist` | `{ agentRecipientRoot, recipientAllowlisted, proofSupplied } \| null` | non-null iff `agentSpend`; both booleans must be `true` to verify |
| `approvals` | `{ aboveThreshold, approvalThreshold, requiredM } \| null` | non-null iff `agentSpend`; `requiredM` = the vault's approvalM |
| `limits` | `{ policyBefore, policyAfter (§6.4 policy leaf), periodsElapsed (0..1000) } \| null` | non-null iff `agentSpend` |
| `policyMutations` | `[{ field, before, after }]` | the DERIVED exact diff of the 7 state fields, in fixed field order; `[]` for genesis/terminal; each field at most once |
| `warnings` | `[{ code: UPPER_SNAKE, detail }]` | non-fatal observations; hashed, never blocking |
| `unexpectedEffects` | `[{ code, detail }]` | the builder RECORDS anything it cannot explain here; verification REFUSES any manifest where it is non-empty |
| `manifestHash` | hex32 | §5 |

### 6.4 State tuple and agent policy leaf (v0.4 family)

State (exactly `stateToJsonV4`, `sdk/src/vault-state-v4.js`):

```
{ protectedValue (>0), feeReserve, paused ("0"|"1"), agentRoot (hex32),
  approverSlots: exact 10 slots (hex32; sentinel = 64 zero hex,
                 active keys distinct),
  approvalM (0..10; 0 iff no active approvers, else 1..activeCount),
  policyNonce (0..1_000_000_000) }
```

Agent policy leaf (exactly `normalizeAgentPolicyV4`,
`sdk/src/agent-merkle-v4.js`):

```
{ agentPk, maxPerSpend (>0), periodBudget (>0), periodLengthDaa (>0),
  periodStartDaa, periodSpent, approvalThreshold, agentMaxFeePerTx,
  agentRecipientRoot }
```

### 6.5 Decoded transaction

Exactly the `canonicalFrozenTxJson` field set
(`sdk/src/frozen-tx-v3.js`) plus `txId`:

```
{ txId (hex32), version: 1, lockTime (digits),
  subnetworkId: 40 zero hex (native), gas: "0", payload: "",
  inputs:  [{ previousOutpoint {transactionId, index}, sequence (digits),
              computeBudget (int ≤ 0xffff),
              utxo { amount (>0), scriptPublicKey {version, scriptHex},
                     covenantId (hex32|null), blockDaaScore (digits) } }],
  outputs: [{ value (>0), scriptPublicKey {version, scriptHex},
              covenant { authorizingInput (int), covenantId (hex32) } | null }] }
```

The frozen form is the security object: for version-1 Kaspa
transactions the txId excludes signature scripts, so this txId equals
the final broadcast txId. Bridging from a real SDK build:
`JSON.parse(canonicalFrozenTxJson(build.frozen))` + `build.txId`.

Structural consistency (validation-level): an input is classified
`covenant` iff its UTXO carries a `covenantId`; an output is classified
`successor`/`genesisVault` iff it carries a covenant binding.

Per-action transaction shapes (verification-level, mirroring
`vault-builders-v4.js` exactly):

| action | inputs | outputs |
|---|---|---|
| `agentSpend` | `[covenant]` or `[covenant, external]` | `[payment, successor]` or `[payment, successor, change]` — fuel input ⇔ change output. (Corrected 2026-08-26: the authoritative SDK builder emits payment at index 0 and successor at index 1; the pre-fix spec/engine had these reversed and refused every real agent spend — caught by the real-builder bridge test, fixed in `core/intent/verify.js`.) |
| owner mutations | `[covenant, external]` | `[successor, change]` |
| `ownerRecover` | `[covenant, external]` | `[recoverPayout, change]` |
| `createVault` | `[external × 1..n]` | `[genesisVault, change]` or `[genesisVault, agentFuel, change]` |

### 6.6 Accounting

The exact 11 digit-string fields of the v0.4 builder
(`vault-builders-v4.js build.accounting`):

```
predecessorProtected, predecessorFeeReserve, payAmount,
reserveConsumed, externalIn, externalOut, fee,
successorProtected, successorFeeReserve, successorTotal,
terminalPayout
```

## 7. Fail-closed detection catalogue (normative)

`verifyIntentManifest({ manifest, requestedIntent, decodedTransaction })`
runs, in order:

**0. `manifest-valid`** — the complete §6 validation, including the hash
recomputation. Failure hard-stops (no detector runs over an untrusted
structure). Codes: `UNKNOWN_MANIFEST_VERSION`, `UNKNOWN_INTENT_VERSION`,
`UNSUPPORTED_COVENANT_VERSION`, `UNKNOWN_ACTION`, `SCHEMA_INVALID`,
`VALUE_INVALID`, `MANIFEST_HASH_MISMATCH`.

Then the full catalogue (ALL detectors run; ALL failures reported):

| Detector | Refusal codes | Proves |
|---|---|---|
| `intent-binding` | `REQUEST_MISMATCH` | the caller's requested intent is canonically identical to the embedded intent (skipped when not supplied) |
| `transaction-binding` | `TX_MISMATCH` | the caller's independently decoded transaction is canonically identical to the embedded one — the manifest describes THIS transaction (skipped when not supplied) |
| `tx-shape` | `ACTION_TX_SHAPE_MISMATCH`, `UNEXPECTED_OUTPUT` | the transaction has EXACTLY the requested action's input/output shape (§6.5 table); any extra output beyond the shape is unexpected |
| `predecessor` | `PREDECESSOR_MISMATCH`, `ACCOUNTING_MISMATCH` | input 0 spends the declared predecessor outpoint, with the vault's covenantId, carrying exactly predecessor protectedValue + feeReserve |
| `successor` | `WRONG_SUCCESSOR`, `ACCOUNTING_MISMATCH` | exactly one covenant-bound output; bound to the vault's covenantId, authorized by input 0; value = declared successor protectedValue + feeReserve; `stateAfter.expectedOutpoint` names this transaction's covenant output |
| `outputs-explained` | `HIDDEN_RECIPIENT`, `UNEXPECTED_OUTPUT`, `TERMINAL_PAYOUT_MISMATCH`, `REQUEST_MISMATCH` | every output's script and value is justified: payment pays exactly the declared recipient (P2PK), change returns to the signer, the recovery payout pays the owner exactly protected+reserve, genesis agent fuel pays the requested agent |
| `value-conservation` | `VALUE_CONSERVATION_VIOLATION`, `ACCOUNTING_MISMATCH`, `TERMINAL_PAYOUT_MISMATCH` | the exact sompi ledger: Σin − Σout = fee; externalIn/externalOut/payAmount match the classified sums; non-terminal identity fee = (predTotal − succTotal) − pay + externalIn − externalOut; spend drawdown = pay + reserveConsumed; terminal payout = predTotal; genesis fee = funding − vault − change |
| `fee` | `EXCESSIVE_FEE`, `VALUE_CONSERVATION_VIOLATION` | fee ≥ 1; fee ≤ requested `maxFeeSompi` when a cap was requested |
| `request-equations` | `REQUEST_MISMATCH` | every requested parameter equals the manifest's value: recipient, payAmount, periodsElapsed, reserveConsumed, newAgentRoot, approver configuration, top-up deltas, genesis initial state, owner |
| `state-transition` | `STATE_MISMATCH`, `HIDDEN_POLICY_MUTATION` | the frozen field-preservation matrix (§6.1): every field outside the action's authorized set is preserved; the authorized changes follow the exact covenant equations (spend deltas, strict top-up increase, pause direction, no transition to a zero-approver configuration, spend requires unpaused, a spend always changes the agentRoot) |
| `nonce-rule` | `NONCE_RULE_VIOLATION` | policyNonce preserved / incremented by exactly 1 per the §6.1 table |
| `policy-mutations-declared` | `POLICY_MUTATION_MISDECLARED` | the declared diff equals the recomputed stateBefore→stateAfter diff exactly (no undeclared, no phantom mutations) |
| `limits` | `LIMIT_VIOLATION`, `LOCKTIME_RULE_VIOLATION`, `RESERVE_RULE_VIOLATION`, `APPROVAL_TIER_MISMATCH`, `AGENT_POLICY_MISMATCH`, `ALLOWLIST_MISMATCH`, `ALLOWLIST_NOT_PROVEN` | the exact v0.4 agent arithmetic: pay ≤ maxPerSpend; period rollover (newStart = start + periods×length, newSpent reset) with tx lockTime = newStart (CLTV) on rollover, 0 otherwise; newSpent ≤ periodBudget; policyAfter = policyBefore with exactly the period fields advanced; reserveConsumed ≤ agentMaxFeePerTx and ≤ available reserve; aboveThreshold ⇔ pay > approvalThreshold; requiredM = the vault's approvalM (≥1 when above threshold); allowlist root = the policy's agentRecipientRoot; membership recorded proven |
| `authority` | `AUTHORITY_EXPANSION` | defense-in-depth catalogue of unexplained authority increases: approval configuration changed outside `ownerSetApprovers`; agentRoot changed outside `agentSpend`/`ownerSetAgentRoot`; silent unpause outside `ownerUnpause`; nonce advanced by a non-mutation action; protected value or reserve decreased outside `agentSpend` |
| `unexpected-effects` | `UNEXPECTED_EFFECTS_PRESENT` | the manifest records zero unexplained effects |

Any detector throwing internally produces `VERIFIER_INTERNAL` and
refuses — an error is never a pass.

Result (deep-frozen):

```
{ ok, verdict: "VERIFIED_EXACT" | "REFUSED",
  statement: <the exact §1 sentence> | null,
  manifestHash, txId,
  checks:   [{ id, ok, failures: [{ code, detail }] }],
  failures: [ all failures aggregated ] }
```

Detection catalogue coverage of the required threat classes:

- unexpected outputs → `tx-shape` + `outputs-explained`
- hidden recipients (including value leaving through "change") →
  `outputs-explained`
- excessive / unexpected fee → `fee` + `value-conservation`
- incorrect successor → `successor` + `predecessor`
- altered policy / hidden delegate (agent) changes →
  `state-transition` + `policy-mutations-declared` + `authority`
- hidden owner change → structurally impossible to express: the owner
  is a single template-immutable, hash-bound field, and the owner-op
  actor rule refuses at validation; a successor script encoding a
  different owner is caught by the covenant/preflight layer (§2.1)
- state mismatch → `predecessor` / `successor` / `state-transition` /
  `nonce-rule`
- requested action ≠ serialized transaction → `transaction-binding` +
  `tx-shape` + `request-equations`
- unexplained authority expansion → `authority` (+ `nonce-rule`,
  `state-transition`)

## 8. Build

`buildIntentManifest(inputs)` assembles a manifest from structured
inputs (requested intent; network/vault identity; signer key; the
decoded transaction; effect classifications as plain kind arrays;
states; the 11-field accounting; the spend sections). The builder
DERIVES — callers cannot supply — the action metadata row, the
policy-mutation diff, `stateAfter.expectedOutpoint`, and the manifest
hash; it accepts no verdict field. The result is re-validated through
the full strict schema before it is returned, so the builder can never
emit an invalid manifest. Verification remains a separate, independent
step: build never implies verified.

Determinism: identical structured inputs produce byte-identical
canonical serializations and the identical `manifestHash`, on any
machine, through any storage backend.

## 9. Scope boundary and future work (v1)

- Covered: the complete v0.4-family action set
  (`policyvault-0.4` / `policyvault-0.4.1`), including genesis and the
  terminal recovery, with well-formed states.
- Not covered (refuses, never guesses): `policyvault-0.3` manifests
  (frozen covenant, not in production hosted operation); break-glass
  recovery from CONSENSUS-ACCEPTED-but-malformed genesis states (the
  strict state schema rejects them by design — the SDK's quarantined
  `recoveryParse` path remains the only construction route for those);
  fee/mass recomputation from serialized size (the manifest pins the
  realized fee; mass rules stay in `sdk/src/fee-mass.js`); Merkle
  proof re-verification (§2.1).
- A future v2 would extend additively: its own version string, its own
  hash domain, wider covenant coverage. v1 semantics are frozen by this
  document.

Adversarial-testing terminology note: negative cases in the test suites
are policy-invalid adversarial test manifests/transactions —
authorized negative validation of PolicyVault's own verification layer,
constructed to verify that the verifier refuses policy-invalid
descriptions even when they are internally consistent and correctly
hashed.

## 10. Field provenance (real structures mirrored)

| Manifest element | Authoritative source mirrored |
|---|---|
| state tuple | `sdk/src/vault-state-v4.js` (`stateToJsonV4`, bounds, approver rules) |
| agent policy leaf | `sdk/src/agent-merkle-v4.js` (`normalizeAgentPolicyV4`, leaf field order) |
| decoded transaction | `sdk/src/frozen-tx-v3.js` (`canonicalFrozenTxJson`, frozen-form discipline) |
| accounting | `sdk/src/vault-builders-v4.js` (`build.accounting`, §E4) |
| tx shapes per action | `sdk/src/vault-builders-v4.js` (spend/owner/recover/genesis output layouts) |
| action/role table | `sdk/src/wallet-requests-v4.js` (`ROLE_BY_ACTION`, `planV4` high-level mapping) |
| transition equations + nonce rule | `sdk/src/vault-transitions-v4.js` |
| amount discipline | `sdk/src/amounts.js` (strictly canonicalized further, §3) |
| canonical JSON | `sdk/src/canonical-json.js` (semantics mirrored verbatim; G-2) |
| P2PK script | `sdk/src/approval-package-v3.js` (`p2pkScriptHex`) |

## 11. Claim labels

| Component | Claim |
|---|---|
| Manifest v1 schema + hashing + detector catalogue (this document) | DESIGNED |
| `core/intent/canonical.js`, `manifest.js`, `verify.js`, `index.js` | IMPLEMENTED |
| All of the above, via `core/intent/test/` (75 tests) | UNIT-TESTED |

Nothing in this component is VM-VERIFIED, TESTNET-VERIFIED, or
PRODUCTION-HARDENED, and it is wired into no production path. Wiring it
into the SDK build/finalize pipeline (deriving manifests from real
`buildV4Transaction` outputs and verifying them against real frozen
transactions) is the natural next step and belongs to a separate,
explicitly reviewed change to existing files — out of scope here by
directive.
