# Developer integration example: the authority boundary, offline

**Status: RUNNABLE TODAY, mechanically verified.** This page describes
one real, executable example and its test — both already in this
repository, both passing.

- Example: `sdk/examples/adoption-authority-boundary.js`
- Test: `sdk/test/adoption-example.test.js` (5/5 passing, run with
  `cd sdk && node --test test/adoption-example.test.js`)

## Why this example, and not a bigger tutorial

The single most important thing for an integrator to see is not "how do
I call the API" (that's `quickstart-mcp-agent.md` and the server API
docs) — it's **what actually happens when a delegate tries to exceed its
authority**, proven on the real production byte path, not narrated. This
example builds real v0.4.1 covenant transactions with the same SDK
builders the application uses (`sdk/src/vault-builders-v4.js`), driven
through the real `silverc` compiler and the real `pv_call_encoder` — the
exact bytes a live vault would produce — entirely offline (no Kaspa
node, no network call, no broadcast, no real key).

## What it proves

**(a) A permitted delegated spend builds and finalizes.** An agent with
a maximum-per-transaction cap of 20 KAS, a period budget of 50 KAS, and
an approval threshold of 5 KAS spends 4 KAS to an allowlisted recipient.
It is within every limit, so it builds to exact production bytes with
only the agent's own signature — no approval ceremony needed.

**(b) An over-authority spend is refused deterministically, before any
signature, with a closed error code.** The SAME 4 KAS — itself entirely
policy-valid — is redirected to a recipient that is **not** on the
allowlist. The attempt reuses an allowlisted recipient's real Merkle
proof while declaring the unauthorized recipient: exactly the shape of
transaction a malicious holder of the legitimate delegate private key
could hand-construct and submit directly to a Kaspa node, bypassing
PolicyVault entirely. The SDK runs the identical proof walk the covenant
runs on-chain, so this refusal reflects what consensus itself would do,
not a policy opinion a compromised application layer could be talked out
of. It throws before building, before compiling a successor state, and
before any signature is ever requested — with the closed code
`RECIPIENT_PROOF_INVALID`.

**(c) An owner intervention builds independently.** `ownerPause`, signed
by the owner's own key — a different authority entirely from the
agent's — builds and finalizes on its own, with a separate fuel-funded
fee path (owner operations pin every covenant value exactly, so the
network fee cannot come from the reserve the way an agent spend's can).

## Run it yourself

```bash
cd sdk
node examples/adoption-authority-boundary.js
```

Expected output (abbreviated):

```
(a) permitted delegated spend (4 KAS, allowlisted recipient, agent signs alone)
    built + finalized: txId <64-hex>

(b) over-authority spend: same 4 KAS, redirected to a non-allowlisted recipient
    REFUSED before any signature was requested — code: RECIPIENT_PROOF_INVALID
    vault-builders-v4: recipient proof does not verify for this recipient

(c) owner intervention: ownerPause, signed by the owner's own key
    built + finalized: txId <64-hex>
```

```bash
cd sdk
node --test test/adoption-example.test.js
```

runs the same three scenarios under `node:test` and asserts on the
production-byte facts (`build.contractVersion`, `build.encoderFunction`,
`finalized.txId` shape, `finalized.covenantCallHex.length ==
build.plannedCallHexLength`) and on the exact refusal code — 5/5 passing.

## Prerequisites

Same as the wider SDK test suite (`sdk/test/vault-builders-v4_1.test.js`
is the model this example is built on): a built `~/silverscript`
(`cargo build` → `target/debug/silverc`), a built `tests/vm`
(`cargo build --bin pv_call_encoder`), and `~/rusty-kaspa`'s WASM SDK
built (`wasm/nodejs/kaspa`). See `quickstart-selfhost.md` /
`docs/selfhost-quickstart.md` for the exact build commands.

## Numeric discipline

Every amount in the example is produced by the canonical KAS↔sompi
parser (`sdk/src/amounts.js`, backed by `core/model/amounts.js`) — never
a JavaScript number, never a float, on any funds path.

## What this example does not cover

- It does not sign with, request, or log a real key — every key is a
  throwaway test key constructed in-process.
- It does not exercise `AWAITING_APPROVALS` (approver quorum) flows,
  vault creation (genesis), or reconciliation against a live chain — see
  `sdk/test/vault-builders-v4_1.test.js` and
  `sdk/test/approval-flow-v4_1.test.js` for those, and
  `quickstart-kas-delegated-payment.md` for the live end-to-end path.
- It targets the v0.4.1 KAS profile only, not v0.5 (tokens) or v0.6
  (swaps).
