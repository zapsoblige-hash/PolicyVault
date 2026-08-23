# PolicyVault Test Plan

Layered test architecture, the shipped suites, and the standing rules that
keep the layers honest.

## Layers

Separate, clearly labeled layers — never mixed conceptually:

```
UNIT            pure functions (amounts, state normalization, Merkle trees)
PROPERTY        randomized invariants over parsers/serializers/accounting
VM              real TxScriptEngine execution of the production covenants
ADVERSARIAL VM  policy-invalid transactions (correctly signed) must fail
SDK             build → freeze → sign → finalize → VM preflight, offline
INTEGRATION     production-byte paths driven end-to-end
API             real HTTP handler over a temp data root
BROWSER         real served markup + production app code in jsdom
LIVE TESTNET    chain-verified lifecycles on testnet-10
CRASH-RECOVERY  durable claims across injected crashes + reconciliation
```

## Shipped suites

| Layer | Where | How to run |
|---|---|---|
| SDK / API / BROWSER / UNIT / PROPERTY / CRASH / CONCURRENCY | `sdk/test/*.test.js` (includes hostile suites, sabotage-sensitivity, approval-flow, wallet-session, terminal-vault, network/mainnet gates) | `cd sdk && npm test` |
| VM + ADVERSARIAL VM + production-byte integration | `tests/vm/tests/*.rs` (`v4_1_production`, `v4_1_encoder_integration`, `v4_production`, `v4_encoder_integration`, `v4_sdk_integration`, `v3_production`, `v3_sdk_integration`, `v3_encoder_integration`, v2/v1 suites) | `cd tests/vm && cargo test` |
| Served-app acceptance | `tools/h2-browser-polish-acceptance.js` — real server + real synced testnet-10 node; nothing signed or broadcast | `node tools/h2-browser-polish-acceptance.js` |
| LIVE TESTNET drivers (optional; broadcast on testnet-10 with local test keys) | `tools/testnet-v4_1-*.js`, `tools/testnet-v4-lifecycle.js` | see each file's header |
| Covenant byte identity | `tools/gen_v4.js` / `tools/gen_v4_1.js` / `tools/gen_v3.js` regenerate the frozen contracts byte-identically | `OUT=<file> node tools/gen_v4_1.js && diff` |

## Standing rules

1. **Production-byte rule.** Every component that can change
   consensus-visible bytes (call encoder, exact-state compiler, state and
   transaction serializers, signed-package finalizer) must have an
   integration test that drives its exact output through the downstream
   validator — the real TxScriptEngine or a live node. A harness that
   rebuilds equivalent bytes in-process does not count: that blind spot
   once shipped an encoder defect that passed 100% of VM tests and failed
   every live transaction.
2. **Baselines never shrink.** Frozen covenant versions keep their full
   suites; new work adds suites rather than rewriting old ones.
3. **Failure classification before fixes.** CONTRACT BUG / PRODUCTION CODE
   BUG / TEST BUG / ENVIRONMENT / STALE ASSUMPTION / DEPENDENCY CHANGE /
   UNKNOWN — and funds-safety code is never weakened to satisfy a broken
   harness.
4. **Compilation alone is not proof.** Real VM execution with real
   signatures is the minimum bar for any covenant claim; live testnet
   chain proof is the bar for deployability claims.
5. **Sabotage sensitivity.** Guard code is periodically neutralized
   in-source (and byte-identically restored) to prove each guard's test
   actually goes red — a guard whose removal changes nothing is a blind
   spot. Because these suites mutate shared source files on disk, the SDK
   test files run serially (`node --test --test-concurrency=1` in the
   `npm test` script): a concurrent test-file process could otherwise
   `require()` a module inside a mutation window and fail spuriously. Do
   not remove the flag while any suite mutates source in place.
6. **Adversarial testing is negative validation.** Live adversarial
   coverage means authorized testnet negative-validation transactions
   constructed independently of the application, verifying that consensus
   rejects policy-invalid transactions even when correctly signed by the
   designated agent.

## What the adversarial matrices cover

Wrong signer/agent, wrong recipient, over per-spend cap, cumulative
over-budget, early period reset, forged period start, reduced/unchanged
period accounting, modified policy fields, wrong vault identity, wrong
successor value or state, stolen protected change, extra unauthorized
outputs, missing/multiple successors, unauthorized termination, delegate
recovery attempts, stale-state spends, conflicting prepared spends,
request replay, signed-package tampering, version confusion,
unknown-version fallback, corrupted manifests, crash before/after
broadcast, fee-drain via reserve, forged approvals and non-ALL sighash
approvals, cross-agent authority confusion, cross-network material, and
mainnet-gate bypass attempts.
