# Dedicated hostile AI-agent / prompt-injection security review

**Completion-standard surface 26**
(`docs/postlaunch/FULLSCALE_COMPLETION_ADDENDUM.md`).

## Remediation status (2026-08-26 — coordinator pass on the merged RC tree)

The three MEDIUM findings and the safe LOWs were remediated on the RC lane;
each finding-test was flipped to assert the FIXED behavior.

| ID | Sev | Disposition |
|----|-----|-------------|
| **H-8** | MED funds | **FIXED** — `canonicalAmountParam()` at the v4 plan/create amount boundary rejects JSON numbers/arrays/leading-zeros (no more `String()` laundering); valid string/bigint builds byte-identical. |
| **H-1** | MED deception | **FIXED** — `sanitizeDetail()` strips control/bidi chars + caps length before line rendering in intent/governance/risk explain; a crafted detail can no longer forge a verdict/fee/payment line. |
| **H-2** | MED authority | **FIXED** — additive `policyvault-cli-signing-request/2` carries the manifest; the offline CLI signer verifies (VERIFIED_EXACT) + binds txId + renders intent + refuses on mismatch. `/1` stays blind (documented); offline guarantee preserved. |
| **H-7** | LOW-MED design | **FIXED (top-level)** — v4 request + simulate routes refuse unknown TOP-LEVEL keys (`422 UNKNOWN_FIELD`, permitted set named, hostile text not echoed). **TRACKED FOLLOW-UP:** per-action **params-level** closed schema (action-dependent key tables; bounded — the builder is whitelist-by-construction, unknown params proven never to reach consensus). |
| **H-5** | LOW avail | **TRACKED FOLLOW-UP** — gate the x402 allowlist during `accepts[]` selection (filter to allowlisted destinations before choosing) so one cheap non-allowlisted entry cannot hide payable alternatives. Availability-only; no funds/authority impact. Fix recipe in §H-5. |
| **H-3** | LOW info | **FIXED** — `mcp/src/tools.js` shape-validates `capabilities.apiVersion` (falls back to `"unknown"`), so a malformed value cannot forge/truncate an operator log line. |
| **H-6** | LOW hygiene | **FIXED (prototype lookup)** — x402 + AP2 `EXPLANATIONS` are null-prototype, so a server code of `toString`/`constructor` resolves to `undefined`, honouring the `string\|null` contract. **TRACKED FOLLOW-UP:** additionally shape-validate upstream `error.code` before it enters the durable attempt record (§H-6 recipe). |
| **H-4** | LOW avail | **FIXED** — `intentExplain.structured/humanReadable` tolerate a `null` argument (refuse instead of throwing), honouring the documented TOTAL contract. |

The authority boundary held before and after; the remediation removes the
eroded-seam defects the review found without weakening any existing check.
The two TRACKED FOLLOW-UPs (H-7 params-level, H-5, H-6 code-shape) are all
LOW and bounded (no funds/authority path); recipes are in their sections.

**Claim label: REVIEWED + ADVERSARIALLY TESTED (internal).** This is an
internal adversarial review by the project's own engineering process. It
is **not** an external or independent security review, and nothing here
may be described as "audited" or "externally reviewed".

**Scope of the security claim under test** (addendum §Security model):

> AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT
> ENFORCES FINANCIAL AUTHORITY. SIGNERS RETAIN CUSTODY.
> Natural-language/model/tool output is ALWAYS untrusted. No LLM output
> may cross directly into trusted transaction bytes, addresses, amounts,
> authority changes, signer selection, or policy state without
> closed-schema normalization + deterministic PolicyVault verification.

**Verdict: the claim HOLDS on every funds-authority path probed.** No
probe produced a path by which model output, protocol metadata, hostile
server content, or agent retry behaviour could move funds outside the
covenant's authority, substitute a destination, mutate a verified amount,
change a signer, escalate a capability, or bypass governance/risk.

**Eight findings** were nevertheless recorded, none of them a break of
the authority boundary: two MEDIUM defects that weaken the *client-side
verification and human-deception* defences (H-2, H-1), one MEDIUM
numeric-discipline defect that defeats a deliberate existing guard (H-8),
and five LOW findings. All are listed below with severity,
classification, exact reproduction, and a recommended fix. **No
production file was modified by this review** — findings are reported for
a coordinator or follow-up worker to apply.

---

## 1. Methodology

1. **Read the real surfaces first.** Every agent-reachable entry point
   now in tree was read in full before any test was written: `mcp/`
   (server + schema + tools + envelope + http + idempotency + config),
   `integrations/` (x402 + AP2 adapters, normalizers, constraint
   evaluator, address/amount/JSON guards, payee directory, pv-client),
   `core/explain` (intent + governance), `core/intent` (manifest
   validation + verification), `core/signer/adapters/cli`,
   `mobile/www/js/portable` (verification + air-gap), `web/verify-intent.js`,
   `server/src/api.js` v4 routes and `sdk/src/wallet-requests-v4.js`
   `planV4`, plus `core/risk/interface.js` and `server/src/risk-adapters.js`.
2. **Probe only what existing suites do not.** `mcp/test/mcp-schema-hostile.test.js`
   already covers the hostile-ARGUMENT direction, and `integrations/test`
   already carries 112 adversarial cases (metadata quarantine at
   manifestHash/txid, amount/currency/asset/version/flow/destination
   mutations, SD-JWT downgrade and key injection, disclosure withholding,
   deny-wins composition, replay/conflict, scope boundary, audit
   quarantine). None of that is repeated. Every probe here is an angle
   those suites do not test (the reverse direction, the metadata channel,
   the discovery document, the rendering layer, the signer boundary, and
   the API those layers front).
3. **Drive real code, never mocks of PolicyVault.** The MCP probes run
   the real `mcp/server.js` session over the real stdio framing against a
   real `node:http` stand-in for the *remote API* (the thing being modelled
   as hostile). The adapter probes drive the real `X402Adapter` and the
   real normalizers with real `rusty-kaspa` address decoding. The signer
   probes spawn the real CLI as child processes doing real BIP-340
   signing with throwaway test keys. The normalization probes boot the
   real `server/src/server.js` with a real persisted v0.4 vault and a real
   six-scope machine credential.
4. **Assert the CURRENT behaviour for findings.** A probe that
   demonstrates a defect asserts the vulnerable behaviour with an in-line
   `FINDING H-n` comment, so the suite is green and the gap is documented
   rather than hidden. When a finding is fixed, those specific assertions
   are the ones that must be inverted — each is named in §4.
5. **Bound every finding honestly.** Each finding states what an attacker
   gets *and what they still cannot get*, asserted rather than asserted-by-prose.

### Files

| File | Probes | Layer |
| --- | --- | --- |
| `security/hostile-ai/mcp-agent-boundary.test.js` | M1–M6 (12 tests) | UNIT / ADVERSARIAL |
| `security/hostile-ai/adapter-authority-boundary.test.js` | P1–P5 (10 tests) | UNIT / ADVERSARIAL |
| `security/hostile-ai/explanation-injection.test.js` | E1–E6 (10 tests) | UNIT / ADVERSARIAL |
| `security/hostile-ai/signer-verification-boundary.test.js` | S0–S9 (10 tests) | UNIT / ADVERSARIAL |
| `security/hostile-ai/agent-api-normalization.test.js` | N0–N9 (11 tests) | API / ADVERSARIAL |

Run: `node --test security/hostile-ai/` from the repo root.
**Result: 53/53 pass.** No VM probe binary is required by any probe in this
suite; `~/rusty-kaspa/wasm/nodejs/kaspa` is required (address decoding and
CLI signing) and the API suite boots a real server on a temp data root.

---

## 2. Trust-boundary map

```
                  UNTRUSTED                          |   TRUSTED
                                                     |
 model output / tool arguments ──► MCP closed schema ─┼─► HTTP body
   (mcp/src/schema.js: closed objects, integer-only,  |
    amounts as anchored ASCII decimal strings, depth  |
    + node + size caps, path+rule-only refusals)      |
                                                     |
 x402 PaymentRequired / AP2 mandates ─► adapter ──────┼─► normal PV intent
   (closed key sets; PROPOSAL vs RESTRICTIVE-ONLY vs  |
    AUDIT-ONLY trichotomy; no fourth category)        |
                                                     |
 agent REST call ─────────────────────────────────────┼─► planV4 whitelist
   (NO closed schema — H-7; String() coercion — H-8)  |   (rebuilds params)
                                                     |
 server responses / vault labels / memos / adapter    |
 messages / error text ──► envelope `data` ───────────┼─► model reads as DATA
   (never composed into free text; fixed notice)      |
                                                     |
 ============ deterministic core (the security nucleus) ============
   core/intent  build + verify + manifest hash
   core/governance  classify (recomputed at every decision point)
   core/risk  compose (adapters may only restrict)
   core/explain  render  ◄── H-1 injects here
 ===================================================================
                          │
                          ▼
   Universal Signer Interface ── KasWare (browser: verifies first)
                              ── mobile air-gap (verifies first)
                              ── CLI reference signer (CANNOT verify — H-2)
                          │
                          ▼
              KASPA COVENANT — the only security boundary
```

Reading of the map: there are **three** agent-reachable entry points into
one authoritative pipeline (MCP, protocol adapters, REST/Agent API). Two
of them enforce a closed schema; the third — the one the other two front —
does not (H-7/H-8). There are **three** signer producers; two verify
before producing a signing request, the third structurally cannot (H-2).
Every one of those gaps is *behind* the covenant, which is why the
authority claim survives them.

---

## 3. Probe matrix

### M — MCP / model boundary (`mcp-agent-boundary.test.js`)

| # | Probe | Result |
| --- | --- | --- |
| M1a | Hostile `capabilities.apiVersion` → adapter stderr | **FINDING H-3** |
| M1b | Hostile scope / action / schema / schemaVersion / shape in the discovery document | HOLDS — all fail the adapter CLOSED (`DiscoveryError`, no fallback catalog) |
| M1c | Credential leakage on the anonymous discovery fetch | HOLDS — no `authorization` header on `/capabilities`; present on authenticated routes |
| M2 | Hostile discovery doc tries to conjure a sign / submit / approve / key-export / bypass tool | HOLDS — the blueprint list is static source; discovery can only NARROW; exactly 14 tools, exactly 2 mutating (create/reject) |
| M2b | Argument mutation between validation and the wire | HOLDS — byte-identical passthrough plus only the discovered `schemaVersion` pin |
| M3 | Server free-text into tool names/titles/descriptions/schemas (the model's *instruction* channel) | HOLDS — no marker reachable; instructions are adapter-authored and state the trust boundary |
| M4a | Server body shaped like the envelope itself (forged `status`/`notice`/`tool`/`content`/`replayedIdempotency`) | HOLDS — the adapter owns the frame; forgeries survive only as quoted `data` |
| M4b | Framing-hostile server strings (raw newlines, embedded JSON-RPC frame, NUL/ANSI, U+2028/9, lone surrogate, RTL, homoglyph address, 200-deep nesting) | HOLDS — one line, no raw CR/LF, `content[0].text === JSON.stringify(structuredContent)`, embedded frame never became a message |
| M4c | Non-JSON and oversized (9 MB) server responses | HOLDS — `RESPONSE_NOT_JSON` / `RESPONSE_TOO_LARGE`, adapter-authored detail only, no raw bytes echoed |
| M5 | Retry under a new JSON-RPC id → new key → second durable build | DOCUMENTED BOUND — by design; inert because MCP cannot sign/submit and the covenant caps spending |
| M5b | Same id + args replay; argument key order | HOLDS — replays the first outcome; canonical key-sorted preimage; id `1` vs `"1"` type-tagged |
| M6 | Refusal body carrying an injected "retry to bypass" directive | HOLDS — exactly one attempt, `isError: true`, directive quarantined under `data.error.message` |

### P — protocol adapters (`adapter-authority-boundary.test.js`)

| # | Probe | Result |
| --- | --- | --- |
| P1a | Resource server steers WHICH allowlisted destination is paid (price ordering) | DOCUMENTED BOUND — deterministic PolicyVault-side selection, bounded by the covenant allowlist, digest-bound for audit |
| P1b | One cheap NON-allowlisted entry hides every payable alternative | **FINDING H-5** (availability) |
| P2a | AP2 instrument map lookup with `__proto__` / `constructor` / `toString` / … | HOLDS — fails closed (`AP2_INSTRUMENT_UNKNOWN`) |
| P2b | Payee directory prototype-shaped ids | HOLDS — resolution is over a `Map`; the loader refuses off-grammar ids at load time |
| P2c | `EXPLANATIONS[serverCode]` prototype lookup | **FINDING H-6** (hygiene) |
| P3 | Hostile API `error.code` + injected directive into the agent-facing outcome document (real `X402Adapter`, real attempt store) | **FINDING H-6** — code passthrough; HOLDS on everything else (refusal, no build/simulate call, no requestId, no txId, directive quarantined) |
| P4 | Constraint evaluator: invented "granting" types, prototype-shaped types, unreadable values, hostile budget shapes, order permutations | HOLDS — restrictive-only by construction; every verdict inside `{ALLOW, REVIEW, DENY}`; deny-wins in both orders; empty list ALLOWs only in the "no constraint objected" sense |
| P4b | Line-item prices as an amount oracle | HOLDS — descriptive only; disagreement is REVIEW, never a different paid amount |
| P5 | Hostile audit-only metadata (injection prose, RTL, `extra.payAmountSompi` / `extra.recipient` / `extra.maxFeeSompi`, hostile `extensions`) | HOLDS — normalized intent byte-identical; digest DOES change (bound for audit, not discarded); raw bytes preserved verbatim |
| P5b | Authority-shaped keys at CLASSIFIED depth (requirement level, top level) | HOLDS — `X402_SCHEMA_UNKNOWN_FIELD` |

### E — explanation / rendering (`explanation-injection.test.js`)

| # | Probe | Result |
| --- | --- | --- |
| E1 | Manifest `warnings[].detail` newline injection into a **VERIFIED** pre-signing summary | **FINDING H-1** |
| E2 | `unexpectedEffects[].detail` forging `Verification: PASSED …` inside a **DO-NOT-SIGN** rendering, with 20 blank lines of padding | **FINDING H-1** |
| E3 | ANSI CSI, CR overprint, RTL override in note details | **FINDING H-1** |
| E4 | Hostile `policyMutations[].field` through the validator's refusal text | HOLDS — the validator quotes untrusted values with `JSON.stringify`; no injection |
| E4b | Fabricated `{ok:true}` verification for an unverifiable manifest | HOLDS — independent in-process re-verification overrides it (`EXPLAIN_REVERIFY_REFUSED`) |
| E5 | Governance classifier result that LIES about its lane | HOLDS — recomputation wins (`CLASSIFICATION_MISMATCH`); no reassuring headline |
| E5b | Unknown per-field code with reassuring wording | HOLDS — renders generically under the VALIDATED direction; expansion lane and ceremony unchanged |
| E5c | Non-canonical amount string in a governance per-field value | **FINDING H-1** (governance variant — reaches the HEADLINE) |
| E6 | Malformed inputs: determinism + refusal | HOLDS — byte-identical repeats, every shape refuses |
| E6b | `humanReadable(null)` / `structured(null)` against the documented TOTAL contract | **FINDING H-4** |

### S — signer / verification boundary (`signer-verification-boundary.test.js`)

| # | Probe | Result |
| --- | --- | --- |
| S1a | Does the reference signer's request document carry a manifest or a verification outcome? | **FINDING H-2** — six closed keys, no such slot |
| S1b | Does the signer import verification or render intent? | **FINDING H-2** — no reference to `core/intent`, `core/explain`, `verifyIntentManifest`, `humanReadable`, or `DO NOT SIGN` in either source |
| S1c | Additive `manifest` key today | **FINDING H-2** — refused by the closed schema, so the fix must be a NEW format version |
| S1d | Sign an arbitrary payload with no verification (real child process, real signature) | **FINDING H-2** — status 0, real signature script, zero intent text on stdout/stderr |
| S2 | `authorizeSigning` with absent / refused / half-forged / mis-bound verification | HOLDS — `VERIFICATION_REQUIRED`, `VERIFICATION_REFUSED`, `VERIFICATION_TX_BINDING_MISMATCH` |
| S2b | `buildSigningRequestDocument` without a pass | HOLDS — no document is produced at all (absent, not disabled) |
| S3 | Signer fail-closed on format version / kind / network / signer identity | HOLDS — every refusal carries a machine code in a JSON document |
| S3b | Secret material in any CLI output across the session | HOLDS — the private key never appears |

### N — the normalization boundary itself (`agent-api-normalization.test.js`, real server)

| # | Probe | Result |
| --- | --- | --- |
| N1 | Unknown top-level fields (`bypassPolicy`, `skipGovernance`, `signedSafeJson`, `role`, `orgId`) and unknown `params` (`maxFeeSompi`, `feeSompi`, `lockTime`, `computeBudget`, `approvalThreshold`, `maxPerSpend`, `recipientAddress`, `memo`) | **FINDING H-7** — accepted (200 OK) and silently ignored. HOLDS on the authority half: byte-identical `review`, `manifestHash` and `txId` with and without them |
| N1b | Same field at the MCP layer | HOLDS — `unknown property` refusal (documented asymmetry) |
| N2 | 19 malformed amount forms (floats, exponents, signs, whitespace, unicode digits, booleans, null, objects, overflow, unsafe magnitudes) | HOLDS — all refuse with a machine code |
| N2e | JSON number `100000000`, JSON array `[100000000]`, leading-zero `"01"` | **FINDING H-8** — all three accepted |
| N2b | Identity fields: uppercase, truncated, Cyrillic homoglyph, trailing space, valid-but-not-allowlisted, traversal, null, integer | HOLDS — every one refuses; the allowlisted recipient still builds |
| N2c | `signerAddress` substitution (outsider / recipient / garbage / empty / null) | HOLDS — every one refuses |
| N2d | Unknown / case-variant / injected action strings | HOLDS — fail closed, never routed to a default |
| N3 | Unknown request `schemaVersion` | HOLDS — 422 `SCHEMA_VERSION_UNSUPPORTED` |
| N4 | Repeated hostile dry runs | HOLDS — no durable request, no gate consumed |

---

## 4. Findings

Severity axes: **funds** (can value move wrongly), **authority** (can a
control be bypassed or a signature be obtained wrongly), **availability**,
**info** (deception / disclosure). Classification per CLAUDE.md:
CONTRACT / PRODUCTION / DESIGN.

---

### H-2 — the reference offline signer cannot verify what it signs

**Severity: MEDIUM (authority). Classification: DESIGN.**
**Probes: S1a–S1d.**

`policyvault-cli-signing-request/1` is CLOSED at exactly
`["format","kind","network","expectedSignerAddress","unsignedSafeJson","signInputs"]`
(`core/signer/adapters/cli/cli.js`). There is no slot for an intent
manifest, a requested intent, or a verification outcome, and neither
`cli.js` nor `adapter.js` references `core/intent`, `core/explain`,
`verifyIntentManifest`, `humanReadable`, or the string `DO NOT SIGN`. The
signer therefore does not merely *skip* verification — it **structurally
cannot** verify, and it prints nothing about what the transaction does.

The verification gate lives entirely in the two *producers* that happen to
be clients with a UI: `web/verify-intent.js` and
`mobile/www/js/portable/airgap.js` (whose `authorizeSigning` correctly
refuses absent / refused / mis-bound outcomes — S2). An autonomous agent
that drives the REST/Agent API for the build, writes the signing-request
document itself, and invokes the reference signer reaches a **real
signature with no client-side verification anywhere in the path**. The
completion standard's claim "client independently detects server/frontend
manipulation before signing" is therefore true of the browser and mobile
clients and false of the agent + reference-signer path.

**Repro:** `node --test security/hostile-ai/signer-verification-boundary.test.js`
— S1d generates a keyfile, builds an unsigned transaction, feeds it as a
signing request, and gets a valid Schnorr signature back with exit status
0 and no intent text in any output.

**Bound (asserted):** a compromised coordination layer still cannot exceed
the covenant — recipient allowlist, per-spend cap, period budget, approval
threshold and fee reserve are consensus-enforced. The exposure is
*within-policy* substitution (an allowlisted-but-wrong recipient, a
maximum-permitted amount) precisely in the path where the independent
verifier was supposed to catch it.

**Recommended fix (additive; the current closed schema makes it safe):**
1. Add `policyvault-cli-signing-request/2` carrying
   `manifest` + `requestedIntent` alongside the existing six keys
   (unknown versions already fail closed, so `/1` producers keep working).
2. On `/2`, the CLI runs `verifyIntentManifest`, refuses unless
   `VERIFIED_EXACT` and bound to the exact `unsignedSafeJson`, and prints
   `intentExplain.humanReadable(...)` before signing.
3. Keep `/1` accepted only behind an explicit, documented
   `--unverified-payload` flag whose refusal text names the risk — or
   deprecate `/1` once the mobile producer emits `/2`.
4. Fix H-1 **before** wiring the explanation into a terminal signer:
   otherwise step 2 renders attacker-controlled ANSI/newlines into the
   operator's terminal.

---

### H-8 — `String()` coercion at the v4 planner defeats the canonical amount parser

**Severity: MEDIUM (funds-correctness). Classification: PRODUCTION.**
**Probes: N2e (and N2 for what still holds).**

`core/model/amounts.js parseSompi` deliberately rejects JS numbers — its
own comment reads *"Accepts BigInt directly. Rejects numbers
(floating-point risk)"* — and requires `/^\d+$/`. But
`sdk/src/wallet-requests-v4.js planV4` coerces first:

```js
payAmountSompi: String(params.payAmountSompi),
periodsElapsed: params.periodsElapsed !== undefined ? String(params.periodsElapsed) : "0",
...(params.reserveConsumedSompi !== undefined ? { reserveConsumedSompi: String(params.reserveConsumedSompi) } : {})
// and: topUpAmountSompi, topUpReserveAmountSompi (lines 334, 336)
```

The coercion runs **before** the parser, so the parser's type gate never
fires. Verified against the real server: a JSON number `100000000`, a JSON
array `[100000000]` and the non-canonical string `"01"` are all ACCEPTED
and produce `review.paymentKas` of `1`, `1` and `0.00000001`.

The hazard this opens: **a JSON number above 2^53 is already rounded by
`JSON.parse` before PolicyVault sees it**, and `String()` then yields a
perfectly canonical but *different* amount —
`String(9007199254740993) === "9007199254740992"`,
`String(2900000000000000001) === "2900000000000000000"`. Both are inside
`MAX_SOMPI`. This is exactly the class of defect CLAUDE.md's permanent
numeric-safety rule exists to prevent ("All consensus/accounting values
are integer sompi… Never floating point… Reject… unsafe integers").

**Repro:** `node --test security/hostile-ai/agent-api-normalization.test.js`
— N2e drives the real server.

**Bound (asserted):** floats, exponents, signs, whitespace, unicode
digits, objects, booleans, `null`, overflow and unsafe magnitudes all
still refuse (N2, 19 cases). The value-changing band requires an
agent/intermediary that sends a JSON *number* AND an amount above
2^53 sompi (≈ 90.07 M KAS), so no currently plausible vault is affected —
but the guard that was supposed to make this impossible is inert.

**Recommended fix:**
1. Remove the `String(...)` coercions in `planV4` (all five sites) and
   pass the raw value to the canonical parser, so a non-string type
   refuses with the parser's own message.
2. Tighten `parseSompi`'s grammar from `/^\d+$/` to the canonical
   `/^(0|[1-9][0-9]*)$/` used by the MCP catalog and
   `integrations/lib/amounts-gate.js`, so leading zeros refuse everywhere.
3. Add the same closed type check for `periodsElapsed`,
   `reserveConsumedSompi`, `topUpAmountSompi`, `topUpReserveAmountSompi`
   and the agent-policy amount fields.
4. Regression: keep N2/N2e, inverting the N2e assertions.

---

### H-1 — note details inject fabricated lines into the pre-signing explanation

**Severity: MEDIUM (info / human deception at the signing decision point).
Classification: PRODUCTION.**
**Probes: E1, E2, E3, E5c.**

`core/intent/manifest.js requireDetail` accepts **any** string up to 2000
characters — newlines, CR, NUL, ANSI escapes, RTL overrides — for
`manifest.warnings[].detail` and `manifest.unexpectedEffects[].detail`.
`core/explain/intent-explain.js` interpolates those details into the line
array unquoted:

```js
lines.push(`Warning ${w.code}: ${w.detail}`);   // verifiedLines
lines.push(`- ${f.code}: ${f.detail}`);         // refusalLines
```

Because every renderer displays `outcome.lines` **verbatim and in order**
(`mobile/www/js/platform/ui.js`: *"It composes no sentence of its own
about what a transaction does. That is the whole point: there is exactly
ONE implementation of the text a human reads before authorizing money to
move"*), an embedded newline becomes an additional rendered line.

Demonstrated:

* **VERIFIED path (E1)** — a warning detail adds
  `Fee: 0.00002 KAS.` and
  `Payment of exactly 0.001 KAS to recipient public key ab…` to the
  summary of a genuinely verified 10 KAS spend.
* **REFUSED path (E2)** — an `unexpectedEffects` detail injects
  `Verification: PASSED — THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.`
  into a `!! DO NOT SIGN !!` rendering, with 20 blank lines of padding to
  push the refusal headline off a short screen or terminal.
* **Control characters (E3)** — ANSI CSI (`ESC[2J`, `ESC[H`), CR
  overprinting and bidi overrides all survive.
* **Governance variant (E5c)** — a non-canonical amount string falls
  through `formatValue`'s `String(value)` branch and injects into the
  governance **headline**, the primary decision text of the ceremony UI.

**Repro:** `node --test security/hostile-ai/explanation-injection.test.js`.

**Bound (asserted):** the injection cannot change any verified fact. True
amount/recipient/fee lines are still emitted in full, the manifest hash
still binds, the structured document's `verdict` is unambiguous, and a
refusal still carries no `payment`/`outputs`/`fee`/`balances`/`limits`
block. Also: **no live path feeds these fields today** — `core/intent/bridge/derive.js`
sets `warnings: []` / `unexpectedEffects: []`, and `web/verify-intent.js`
only pushes its own adapter-authored `BROWSER_SERVER_CLAIMED_FIELDS` text
built from literal strings. This is a latent gap in a portable core module
that is exported for general use (`sdk.explain`) and documented as the
place *"an upstream builder that detects something unexplained can RECORD
it"* — i.e. a field designed to be populated by code other than the two
current clients. H-2's recommended fix would turn it into a live path.

**Recommended fix:**
1. In `core/intent/manifest.js requireDetail`, restrict details to
   printable, single-line text: reject any character outside
   `[\x20-\x7E]` plus a documented allowance — at minimum reject
   `\x00-\x1F`, `\x7F`, `U+2028`, `U+2029`, and the bidi controls
   `U+202A`-`U+202E` and `U+2066`-`U+2069` — and keep the 2000-char
   cap. (`requireCode` is already UPPER_SNAKE-constrained and is fine.)
2. Defence in depth in `core/explain`: sanitize at render time too —
   every interpolated untrusted value passes a `oneLine()` helper before
   entering a line, and `formatValue`'s fallback branch uses
   `JSON.stringify` instead of `String` (matching the validator's own
   convention, which E4 proves safe).
3. Regression: keep E1/E2/E3/E5c, inverting the FINDING assertions.

---

### H-7 — the Agent API silently ignores unknown fields (no closed schema)

**Severity: LOW-MEDIUM (authority-adjacent: a silent no-op control).
Classification: DESIGN.**
**Probes: N1, N1b.**

`server/src/api.js` destructures the v4 body
(`const { vaultId, action, params, signerAddress, proposalId, riskEvaluationId } = body ?? {}`)
and `planV4` reads only the fields it knows, so unknown keys are dropped
without comment. A request carrying `bypassPolicy: true`,
`skipGovernance: true`, `params.maxFeeSompi`, `params.recipientAddress`
or `params.memo` returns **200 OK** with a successful build.

This is the one place in the agent-reachable stack where the closed-schema
discipline stated everywhere else — *"a hidden field is a hidden effect,
so unknown keys refuse"* (`integrations/x402/codes.js`), *"unknown
properties are refused, so a hostile or confused model cannot smuggle
extra fields toward the API"* (`mcp/src/schema.js`) — is not applied. The
practical hazard is not smuggling (the planner is whitelist-by-construction)
but the inverse: an agent, or an LLM filling in a half-remembered schema,
**believes it applied a control that does not exist**, and nothing says
otherwise.

**Repro:** N1 in `agent-api-normalization.test.js`.

**Bound (asserted):** with and without the hostile fields, every key of
`simulation.review`, the `manifestHash` and the `txId` are byte-identical.
No unknown field can reach the builder.

**Recommended fix:** add a closed-schema pre-check to the v4 request and
simulate routes (and their governance-proposal siblings) that refuses
unknown top-level and `params` keys with a `422 UNKNOWN_FIELD` naming the
permitted set — mirroring `mcp/src/schema.js`'s path+rule-only refusal
convention so hostile key text is never echoed. Version it with the
existing `schemaVersion` pin so older clients get a clean refusal rather
than a silent behaviour change.

---

### H-5 — x402 selection runs before the allowlist gate

**Severity: LOW (availability). Classification: DESIGN.**
**Probe: P1b.**

`integrations/x402/normalize.js` selects the lexicographically-first
surviving `accepts[]` entry (amount ascending) and the covenant-allowlist
pre-check runs afterwards in `x402/adapter.js`. A resource server that
offers a 1-sompi entry to an address the agent may not pay, alongside a
genuine payable entry, causes the unpayable entry to be selected and the
whole attempt refused `X402_DESTINATION_NOT_ALLOWLISTED` — the payable
alternative is never reconsidered. The `attemptId` is consumed, so a
re-drive with the same id + digest replays the refusal and the caller must
mint a fresh `attemptId`.

**Bound (asserted):** availability only. No funds move, no destination is
substituted, and the refusal is free (it happens before any durable build).

**Recommended fix (optional, and *only* if the allowlist can be consulted
without weakening anything):** pass the acting agent's recipient set into
the selection step as an additional *survivor filter* (never as a
tiebreaker that could be steered), so non-allowlisted entries are refused
per-entry into `perEntryRefusals` like any other failed gate, and the
cheapest **payable** entry wins. If that coupling is judged undesirable
(it makes a pure normalizer depend on vault state), record the behaviour
explicitly in `x402-adapter-spec.md` §3.3 instead — the point is that it
should be a decision, not an accident.

---

### H-3 — unvalidated `capabilities.apiVersion` forges an MCP diagnostic line

**Severity: LOW (info / deception). Classification: PRODUCTION.**
**Probe: M1a.**

`mcp/src/tools.js` documents its stance as *"every value taken from it is
shape-validated against strict ASCII patterns first"*, and `scopes`,
`actions.v4`, `schemas.walletV4Request` and `networkId` all are.
`apiVersion` is not: it reaches `diag()` with only `.slice(0, 32)` applied.
Since `diag()` writes `policyvault-mcp: ${line}\n`, an embedded newline
splits the diagnostic into two lines, and the attacker supplies the second
line's full text (including a convincing `policyvault-mcp: ` prefix). The
authentic line is truncated at the injection point, destroying real
diagnostic information. The discovery fetch is `anonymous: true`, so
anything able to answer it — a compromised API, or a MITM on the plaintext
transport `POLICYVAULT_MCP_ALLOW_INSECURE_HTTP` permits — can do this. Many
MCP clients surface server stderr in logs or to the user.

**Bound (asserted):** ≤ 32 characters per session, stderr only. stdout
stays pure JSON-RPC (asserted on every emitted line) and the tool catalog
is unchanged (14 tools).

**Recommended fix:** validate `apiVersion` in `normalizeCapabilities` with
`/^[A-Za-z0-9._-]{1,32}$/`, defaulting to `"unknown"` like `networkId`
does (or failing closed). Additionally, strip `[\r\n]` from any
interpolated value inside `diag()` itself as defence in depth.

---

### H-6 — server-controlled machine codes and prototype lookups in adapter outcomes

**Severity: LOW (info / typed-output hygiene). Classification: PRODUCTION.**
**Probes: P2c, P3.**

`sdk/src/http-client.js` accepts any string as `error.code`
(`typeof envelope.code === "string" ? envelope.code : "UNKNOWN"`), and
`integrations/x402/adapter.js` places it directly into the agent-facing
outcome (`codes: [error.code, ...]`) and looks it up in a plain object
(`explanations: codes.map((c) => EXPLANATIONS[c] ?? null)`). Because
`EXPLANATIONS` is an object literal, a code of `toString` / `constructor`
resolves to an **inherited function**, so the `explanations` slot violates
its own `string | null` contract (`?? null` only guards `undefined`).
Driven end-to-end against the real `X402Adapter` in P3.

**Bound (asserted):** the attempt still fails closed — status `REFUSED`,
`requestId: null`, `txId: null`, and no `/wallet/v4/` call was ever made.
The injected instruction text is quarantined under `refusalReason` and
never acted on. This is an output-typing and audit-integrity defect, not a
path to authority.

**Recommended fix:** build `EXPLANATIONS` (both x402 and AP2) with
`Object.create(null)` or a `Map`, and guard the lookup with
`Object.prototype.hasOwnProperty.call`. Separately, shape-validate
server-supplied codes before they enter `outcome.codes` (e.g.
`/^[A-Z][A-Z0-9_]{0,63}$/`, else record `UPSTREAM_CODE_UNRECOGNIZED` and
keep the raw string under `refusalReason`), so the durable attempt record
cannot be seeded with arbitrary text.

---

### H-4 — `intentExplain` is documented TOTAL but throws on `null`

**Severity: LOW (availability / fail-open risk in a caller).
Classification: PRODUCTION.**
**Probe: E6b.**

`core/explain/intent-explain.js` states *"Both entry points are TOTAL:
they never throw. Malformed inputs and internal errors produce a REFUSAL
explanation (an error is never a pass, and a signer UI always gets
something safe to display)."* The destructuring default
`({ manifest, verification } = {})` fires only for `undefined`, so an
explicit `null` — the natural value for "no outcome yet" or a failed
upstream fetch — throws a `TypeError`. A renderer that guards with
`try/catch` then shows an empty or neutral state instead of the
DO-NOT-SIGN ceremony. `governanceExplain` is genuinely total (asserted).

**Recommended fix:** normalize the argument at entry
(`const a = input && typeof input === "object" ? input : {}`) in both
`structured` and `humanReadable`, and add `null` to the E6 case list.

---

## 5. What this review did NOT cover

Stated explicitly so the surface-26 claim is not read wider than the work.

1. **Signed webhooks / asynchronous events (surface 18)** as a
   hostile-data vector — event payload construction, delivery signing, and
   consumer-side replay were not probed. `server/src/events-signing.js`,
   `events-delivery.js` and `webhooks.js` were not read for this review.
2. **The Python reference client** (`python/`) — not probed. The
   conformance suite exercises it for equivalence, not for hostile input.
3. **Risk adapters as a live untrusted channel.** `core/risk/interface.js`
   was READ and is closed-schema and fail-closed by construction (unknown
   adapter fields, contract versions, capabilities, result fields and
   verdict strings all refuse; adapter errors can only yield REVIEW or
   DENY, never ALLOW; REVIEW/DENY must carry a structured reason), and
   `web/risk-ui.js` HTML-escapes adapter reason text. No adversarial probe
   was written against a hostile external adapter's response, and reason
   `message` text is subject to the same unquoted-rendering question as
   H-1 in any non-HTML consumer.
4. **KasWare / browser end-to-end** — no browser or extension was driven.
   The browser verifier's own suite (`web/test/`) is the authority there;
   this review only traced where its manifest inputs come from.
5. **Multi-agent concurrency under adversarial scheduling** — reservation
   races and budget exhaustion across simultaneous agents (surface 15) were
   not probed; existing suites cover the non-adversarial contract.
6. **Live testnet or mainnet execution** — every probe is UNIT/API layer
   against local processes. No transaction was broadcast. Nothing here is
   TESTNET-VERIFIED.
7. **The covenant itself** — no VM probe was run for this review; covenant
   enforcement is relied upon as the boundary and is proven by
   `tests/vm`. Where a finding's bound says "the covenant still enforces
   X", that rests on those existing VM suites, not on new evidence here.
8. **Organization/tenancy isolation** — covered by the Phase F hostile
   suites and the conformance matrix; not re-probed.
9. **Prompt injection against a specific model or client.** This review
   tests the *channel* (can hostile text reach an instruction position),
   not any particular model's susceptibility. No LLM was in the loop.

---

## 6. Assessment

The addendum's security claim holds where it matters most. The strongest
result is architectural rather than any single test: **the MCP surface has
no signing, submitting, approving, or governance-mutating tool, and no
hostile discovery document can create one** — the blueprint list is static
adapter source and discovery can only narrow it. Combined with the
covenant as the hard boundary, an AI agent that is fully compromised, or
that is fed maximally hostile tool output, can *request* and can *read*;
it cannot *authorize*.

The three MEDIUM findings share one shape, and it is worth naming: **the
defences are strongest at the boundaries that were designed as boundaries
(MCP schema, adapter normalizers, covenant), and weakest at the seams
between them** — the API those adapters front (H-7, H-8), the signer at
the far end of the pipeline (H-2), and the rendering layer that is
supposed to be the human's single source of truth (H-1). None of them
breaks the authority model; all of them erode a defence the completion
standard explicitly claims. H-2 and H-1 interact: fixing H-2 by rendering
explanations in a terminal signer *requires* fixing H-1 first.

Recommended order: **H-8** (smallest change, restores a stated permanent
rule), **H-1** (prerequisite for H-2), **H-2** (additive format version),
then **H-7**, **H-5**, **H-3**, **H-4**, **H-6**.
