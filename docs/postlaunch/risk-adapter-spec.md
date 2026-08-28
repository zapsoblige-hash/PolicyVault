# PolicyVault Pluggable Risk / Compliance Hooks — Program D v1

Status: **DESIGNED** (this framework) / composition core **IMPLEMENTED +
UNIT-TESTED** (`core/risk/`, 32/32 `node --test`). No covenant bytes
changed. Not externally reviewed. LATER WAVES (release-candidate lane;
this document's §7 table predates them): the server wiring now EXISTS
(`server/src/risk.js` — per-org adapter config, intent-stage gate,
durable evaluation evidence, REVIEW hold release with read-side
intent↔hash re-verification) and the deterministic EXPLANATION renderer
exists (§5.5, W4-refinements).

Related: `docs/postlaunch/governance-spec.md` (Program B),
`docs/hosted-threat-model.md` (server/DB compromise verdicts),
`docs/organization-model.md` (org metadata plane).

---

## 1. Purpose and the hard invariant

Organizations adopting PolicyVault for treasury operations often already
run compliance and risk infrastructure — sanctions screening, KYT
analytics, ERP purchase-order matching, fraud models. Program D defines
ONE pluggable evaluation surface so those systems can participate in
PolicyVault's spend workflow **without ever becoming a spending
authority**.

**INVARIANT (2), stated hard and repeated at every layer:** off-chain
risk/compliance controls may make PolicyVault MORE restrictive; they may
NEVER override a covenant denial and NEVER substitute for covenant
verification. Composition is deny-wins. A risk `ALLOW` is not an
authorization — it merely declines to add a restriction. The covenant's
caps, budgets, allowlists, approval tiers, and conservation rules are
enforced by Kaspa consensus whether or not any adapter exists, agrees,
errs, or is compromised. Structurally, the framework's policy gate
(`applyRiskToPolicyDecision`, §5.3) has no code path that consults the
risk verdict once the policy decision is DENY.

Free-forever note: risk hooks are part of the free product like every
security feature. The adapter interface is open (Apache-2.0 public
policy); PolicyVault never charges for it and never gates security
behind it.

## 2. Where risk evaluation sits in the pipeline

The released pipeline discipline is unchanged:
`intent → build → sign → finalize → submit → reconcile`.

Risk evaluation runs at the INTENT stage, before any wallet request is
built or any signature prompt appears:

```
transactionIntent ──► policy preflight (SDK mirrors covenant rules)
        │                    │
        │                    ├─ DENY ──────────────► REFUSED (final; risk not consulted)
        │                    └─ ALLOW
        ├──────────────────► evaluateRisk(adapters, intent, context)
        │                          │
        │                          ├─ DENY ───────► REFUSED (restrictive, with reasons)
        │                          ├─ REVIEW ─────► HELD for human review (org workflow)
        │                          └─ ALLOW ──────► proceed to build → wallet signing →
        │                                           covenant/consensus (the real boundary)
```

- REVIEW holds the workflow for a human decision (org-configurable who);
  a human release proceeds to build/sign — it does not skip any covenant
  rule. A human may also convert REVIEW to a refusal.
- Adapters are consulted again only if the intent changes (a changed
  intent is a new evaluation); results are recorded with the request for
  audit.
- Nothing downstream of `build` consults adapters: signing, finalize,
  submit, and reconcile keep their existing, proven semantics. An
  adapter cannot un-sign, un-submit, or roll back chain truth.

## 3. The adapter contract (`policyvault-risk-adapter/1`)

An adapter is a registered object (validated by
`core/risk/interface.js` `validateAdapterDefinition`):

```
{
  name:            /^[a-z0-9][a-z0-9-]{0,63}$/,     // unique per registry
  adapterVersion:  "<implementation version string>",
  contractVersion: "policyvault-risk-adapter/1",     // exact; unknown ⇒ refuse
  capabilities:    [ <catalogue id | "x-..." extension>, ... ],  // ≥1
  evaluate(transactionIntent, organizationContext) → Promise<verdictResult>,
  timeoutMs?:      1..600000                          // per-adapter override
}
```

Verdict result (validated by `validateVerdictResult`; unknown fields,
unknown verdict strings, or a restrictive verdict without a reason all
refuse and are then handled as adapter errors — §5.2):

```
{
  verdict: "ALLOW" | "REVIEW" | "DENY",              // exact, case-sensitive
  reasons: [ { code: /^[A-Z0-9_]{1,64}$/,
               message: <non-empty string>,
               evidence?: <JSON-safe object> }, ... ] // ≥1 for REVIEW/DENY
}
```

Versioning discipline: the contract version is part of the definition and
is matched exactly — a future `policyvault-risk-adapter/2` is a new
contract, never a silent widening of `/1`. Unknown contract versions,
unknown capabilities (outside the catalogue and the `x-` extension
namespace), and unknown verdicts all FAIL CLOSED.

### 3.1 Inputs — and the privacy boundary

`transactionIntent` is the intent MANIFEST: the JSON-safe description of
the proposed operation the SDK already builds (network, `vaultId`,
`sdkAction`, `payAmountSompi` as a decimal string, `recipient`
x-only key / address form, role, budget context). `organizationContext`
is org metadata (org id, labels, `riskPolicy` configuration, member role
labels — the `docs/organization-model.md` plane).

**Privacy note (hard):** adapters receive intent manifests and org
metadata — DATA, never key material. There is no key material to leak:
no seed, private key, or signing secret exists anywhere server-side
(proven; `docs/hosted-threat-model.md` §3). Adapters also never receive
session tokens or auth challenges. Operators should still treat adapter
endpoints as metadata-sensitive (they learn spending patterns) and pin
them in configuration; an adapter is a data processor, not an authority.
Both inputs are passed as deep-frozen clones: an adapter cannot mutate
what other adapters or the caller see (regression-tested).

### 3.2 Registration

`createAdapterRegistry()` — ordered, duplicate names refuse. Registration
is deployment configuration (self-hosted operators and hosted org admins
configure their own adapter sets). Registering an adapter grants it no
authority: the maximum power of ANY adapter, correct or hostile, is to
say DENY or REVIEW. A hostile adapter is a denial-of-service risk
(bounded by timeouts and by the operator's choice to remove it), never a
spend risk.

## 4. Integration catalogue

Capability ids (`ADAPTER_CAPABILITIES`) with the intended integration
shape. Every integration is restrictive-only by construction.

| Capability | Integration | Typical verdict use |
|---|---|---|
| `kyt` | Know-your-transaction chain analytics (address risk, cluster exposure) | DENY on high-risk recipient, REVIEW on medium |
| `aml` | AML screening programs | DENY/REVIEW per program policy |
| `sanctions` | Sanctions / watchlist screening of recipients | DENY on hit; unreadable recipient ⇒ DENY (never guess) |
| `fraud-scoring` | Behavioral anomaly / fraud models | REVIEW above score line, DENY at extremes |
| `vendor-validation` | Vendor master-data match (is this recipient a registered vendor?) | REVIEW/DENY on unknown vendor |
| `erp` | ERP integration: PO existence, three-way match | REVIEW until matched, DENY on mismatch |
| `procurement` | Procurement workflow state (approved requisition?) | REVIEW/DENY |
| `invoice` | Invoice validation (amount/recipient/reference match) | REVIEW/DENY |
| `accounting` | Ledger-coding / budget-line checks | REVIEW |
| `custom-policy` | Custom enterprise policy APIs | any restrictive semantics |
| `ai-classifier` | AI/ML transaction classifiers | REVIEW (recommended ceiling: AI output should route to humans, not auto-DENY, unless the org opts in) |
| `x-*` | Operator extensions | restrictive-only, same contract |

Mock reference implementations ship in `core/risk/mock-adapters.js`
(threshold, screening, throwing/hanging/malformed fixtures) — they define
the contract by example and drive the composition tests.

## 5. Composition semantics (`core/risk/compose.js`)

### 5.1 Deny-wins fold

`composeVerdicts(verdicts)`: `DENY` > `REVIEW` > `ALLOW`. All adapters
run (no short-circuit) so the audit record carries every reason;
composition happens after. Unknown verdict strings refuse.

### 5.2 Errors, timeouts, malformed verdicts — never silent ALLOW

Configuration (`normalizeCompositionConfig`, all unknown values refuse):

- `onAdapterError: "REVIEW" | "DENY"` (default `REVIEW`). `"ALLOW"` is
  REFUSED at configuration time — an erroring control can never resolve
  permissive. Applies to: thrown errors (sync or async), timeouts
  (`ADAPTER_TIMEOUT`), and malformed/unknown verdict results
  (`ADAPTER_VERDICT_INVALID` / `ADAPTER_VERDICT_UNKNOWN`).
- `timeoutMs` (default 5000, per-adapter override): a hanging adapter is
  a bounded REVIEW/DENY, not a hung workflow and not an ALLOW.
- `onEmpty: "ALLOW" | "REVIEW" | "DENY"` — the empty-adapter-set
  outcome. Default: `ALLOW` for plain/personal contexts (a personal
  vault with no adapters configured is simply not using Program D),
  but `REVIEW` when `organizationContext.riskPolicy.reviewRequired ===
  true`. For a review-required organization, `onEmpty: "ALLOW"` is
  REFUSED as contradictory (`RISK_CONFIG_CONFLICT`) — default-restrictive
  for review-required orgs, by construction.

Every synthesized (error-path) verdict carries a structured reason with a
machine code, so refusals stay legible (the G-1 lesson).

### 5.3 The policy gate — structural override impossibility

`applyRiskToPolicyDecision({ policyDecision, riskDecision })`:

- `policyDecision ∈ {ALLOW, DENY}` — the outcome of PolicyVault's own
  policy pipeline (SDK preflight mirroring covenant rules; ultimately
  the covenant itself). Unknown values refuse.
- `policyDecision === DENY` ⇒ `{final: "DENY", source: "policy"}`
  unconditionally. The risk verdict is not read on this branch — not
  ALLOW, not garbage, not anything (property-tested across arbitrary
  inputs). This is the structural form of invariant (2).
- `policyDecision === ALLOW` ⇒ the risk decision passes through
  (`ALLOW`/`REVIEW`/`DENY`); unknown risk decisions refuse.

And beneath the software entirely: the covenant validates every
transition on-chain. Even a hypothetical bug that returned ALLOW
everywhere could not move a single sompi beyond what covenant rules +
wallet signatures already authorize — adapters sit strictly ABOVE the
security boundary. (Consistent with the proven compromised-server
analysis: the hosted layer holds no keys and consensus is independent.)

### 5.4 `evaluateRisk` result

```
{
  decision: "ALLOW" | "REVIEW" | "DENY",
  results:  [ { adapter, adapterVersion, status: "OK"|"ERROR"|"TIMEOUT",
                verdict, reasons, errorCode? } ... ],   // input order
  codes:    [ sorted unique reason codes ],
  config:   { onAdapterError, onEmpty, timeoutMs, reviewRequired }
}
```

Frozen, JSON-safe (amounts as decimal strings; BigInt refuses at the
boundary — `requireJsonSafe`). Stored with the wallet request for audit;
like every stored artifact it is display/audit data, never authority.

### 5.5 Explanation rendering (W4-refinements — `core/explain/risk-explain.js`)

`riskExplain.structured()/.humanReadable()` turn an `evaluateRisk`
result or the server's stored evaluation record into deterministic
explanation documents/lines (portable; bundled into the browser as
`window.PolicyVaultCore.riskExplain`, consumed by
`web/gov-risk-explain.js`). The renderer NEVER re-decides risk — but it
applies the governance §7.1 stored-label-distrust pattern to every
property of the record that is recomputable FROM the record: the
composed `decision` is recomputed with the deny-wins fold over the
stored per-adapter verdicts, `codes` are recomputed from the stored
reasons, ERROR/TIMEOUT results may never carry ALLOW (and must match
`config.onAdapterError` when present), and the lifecycle `status` must
be consistent with the decision. Any divergence REFUSES loudly
(`DECISION_MISMATCH`, `CODES_MISMATCH`, `ERROR_PATH_ALLOW`,
`STATUS_MISMATCH`, …) instead of narrating the record.

**Integrity boundary (stated honestly, in the module and in every
rendered trust note):** unlike a governance classification — which every
consumer recomputes from the proposal's before/after tuples — the
per-adapter verdicts are stored EVIDENCE of past adapter executions and
are not re-derivable at render time. The renderer therefore verifies the
record's SELF-CONSISTENCY, no more: a record forged consistently in
every field is not detectable client-side. The `intent`↔`intentHash`
binding is separately re-verified server-side before any released hold
is trusted (`server/src/risk.js assertEvaluationIntegrity`), and none of
this is authority: even a fully forged risk record is restrictive-only
coordination bounded by the covenant.

## 6. Fail-closed and numeric rules (invariants 3–4)

- Unknown adapter contract versions, capabilities, verdict strings,
  config values, and policy decisions REFUSE (`RiskRefusal`, machine
  codes, `failClosed: true`).
- Intent/context must be plain JSON-safe objects: BigInt, undefined,
  functions, non-finite numbers, and non-plain objects refuse. Sompi
  amounts travel as base-10 decimal strings (`payAmountSompi`); the
  reference mocks parse them with BigInt and DENY on anything
  unreadable — a screening control that cannot read the amount never
  allows.
- Finite JS numbers are permitted ONLY for non-consensus quantities
  (scores, counts, durations); consensus amounts as numbers do not occur
  in intent manifests (the SDK builders emit decimal strings).

## 7. Implementation status and evidence

| Component | Claim | Evidence |
|---|---|---|
| Program D framework (this document) | DESIGNED | — |
| `core/risk/interface.js` (contract validation, registry, JSON-safety) | IMPLEMENTED + UNIT-TESTED | `core/risk/test/interface.test.js` — contract-version refusal, capability refusal + `x-` extensions, strict verdict validation (unknown verdicts, silent restrictive verdicts, evidence JSON-safety), registry order/duplicates |
| `core/risk/compose.js` (deny-wins composition, error/timeout policy, policy gate) | IMPLEMENTED + UNIT-TESTED | `core/risk/test/compose.test.js` — full composition matrix, empty-set defaults incl. review-required conflict refusal, sync/async throw + hang + malformed-verdict paths never ALLOW, frozen-clone isolation, policy-gate matrix + property test that no risk input (including ALLOW and garbage) upgrades a policy DENY |
| `core/risk/mock-adapters.js` (reference/fixture adapters) | IMPLEMENTED + UNIT-TESTED | exercised throughout `compose.test.js` |
| Server wiring (org adapter config, REVIEW hold workflow, audit records) | IMPLEMENTED in a later wave (this table's original "DESIGNED only" claim is superseded) | `server/src/risk.js` + `server/src/risk-adapters.js`; sdk/server risk suites |
| Explanation renderer (`core/explain/risk-explain.js`, §5.5) | IMPLEMENTED + UNIT-TESTED + bundled (browser seam active) | `core/explain/test/risk-explain.test.js` (17/17, incl. real-`evaluateRisk` producer-boundary cases); crossruntime bundle equivalence; `web/test/gov-risk-explain.test.js` REAL-bundle tamper-refusal proofs |

Test totals for this program's core: **32/32** (`node --test
core/risk/test/`). No existing file was modified.

## 8. Open questions (for the owner / next phase)

1. REVIEW-release authority: which org role labels may release a REVIEW
   hold (proposal: `owner`/`administrator`/`treasurer` configurable, with
   the acting signer never releasing their own hold)?
2. Should hosted PolicyVault offer any first-party adapters, or ship
   adapter SDK + mocks only and leave integrations entirely to
   operators? (Leaning: interface + mocks only; neutrality.)
3. Result retention: full adapter evidence in the audit trail vs codes
   only (privacy of third-party screening payloads).
4. Whether per-vault (not just per-org) adapter sets are wanted for
   personal power users.
