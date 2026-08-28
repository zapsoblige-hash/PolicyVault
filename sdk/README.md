# PolicyVault SDK (JavaScript / TypeScript)

Two things in one package:

1. **Deterministic local verification.** Portable, offline, zero-dependency
   modules — canonical amounts, canonical JSON, vault state and successor
   derivation, Merkle commitments, fee/mass arithmetic, approval packages,
   frozen-transaction commitments, and transaction-intent manifests — so you
   can *independently check* what a PolicyVault deployment tells you instead
   of trusting it.
2. **An API client.** A zero-dependency `fetch` client for the PolicyVault
   REST/Agent API, with automatic idempotency keys, versioned request
   bodies, and errors carried back verbatim.

Requires Node.js ≥ 18 (global `fetch`), or any modern browser / WinterCG
runtime for the deterministic modules and the client.

---

## What this is NOT

**PolicyVault is not a custody tool, and neither is this SDK.**

- It **never** asks for, accepts, stores, transmits, derives, or signs with a
  seed phrase, private key, or wallet backup. There is no key material
  anywhere in the public surface and no code path that would accept one.
- It **cannot** authorize a spend. Financial authority lives in the Kaspa
  covenant. A signature comes from *your* signer (KasWare, an offline/CLI
  signer, hardware — anything implementing the Universal Signer Interface).
  This SDK builds requests and checks answers; it never holds custody and
  never substitutes for a signature.
- A PolicyVault server, its database, and its operator are **coordination
  infrastructure, not authority**. A compromised server can lie to you — the
  point of the deterministic modules is that you can catch it.

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT
> ENFORCES FINANCIAL AUTHORITY. SIGNERS RETAIN CUSTODY.**

---

## Status and availability

This package is **`"private": true`** and is **not published to npm**.
PolicyVault's source publication is a deliberate owner-controlled gate, and
nothing in this SDK infers, implies, or advances that authorization. Today it
is consumed in-repo (`server/`, `web/`, `tools/`, the test suites).

Claim labels for this package, per the project's progress-reporting
discipline: **DESIGNED + IMPLEMENTED + UNIT-TESTED + INTEGRATION-TESTED**
(the client is exercised against a real spawned PolicyVault HTTP server).
Not TESTNET-VERIFIED as a package, not externally reviewed, not audited.

### Packaging caveat (known, not yet resolved)

`sdk/src/*` re-exports the portable core from `../../core/`, which lives
**outside this package root**. `npm pack` cannot include files above the
package directory, so a tarball built from `files` alone would install
broken. Publishing therefore needs a build step that vendors `core/` into
the package (or a workspace/monorepo layout) — that step does not exist yet
and is not required while the package stays private. In-repo consumption is
unaffected.

---

## Quickstart

```js
const { createClient, parseSompi, sompiToKas } = require("policyvault-sdk");

const client = createClient({
  baseUrl: "http://127.0.0.1:8080",  // "/api/v1" is appended for you
  token: process.env.POLICYVAULT_TOKEN  // omit entirely for a self-hosted server
});

// 1. Ask the server what it can do — never assume a deployment's shape.
const caps = await client.capabilities();
console.log(caps.networkId, caps.contract.supportedCovenantVersions);

// 2. Look around.
const { vaults } = await client.listVaults();

// 3. DRY RUN before anything real (see "Dry-run first" below).
const { simulation } = await client.simulate({
  vaultId,
  action: "agentSpend",
  params: {
    payAmountSompi: "1500000000",   // integer sompi, as a STRING
    agentPk: agentXOnlyHex,
    recipient: recipientXOnlyHex
  },
  signerAddress: agentAddress
});

if (!simulation.ok) {
  console.error("would refuse:", simulation.refusalReason.code, simulation.refusalReason.message);
  return;
}
console.log("exact fee:", sompiToKas(parseSompi(simulation.review.feeSompi)), "KAS");
console.log("intent verdict:", simulation.intent.verdict);   // "VERIFIED_EXACT"
console.log("still requires:", simulation.wouldRequire);     // approvals / proposal / riskRelease

// 4. Only now build the real (unsigned) request.
const built = await client.createRequest({ vaultId, action: "agentSpend", params, signerAddress });
```

A built request is **not** a broadcast. Builders never broadcast: the
pipeline is `intent → build → sign → finalize → submit → reconcile`, and each
stage is a separate call.

---

## Authentication

Two deployment modes, and the client handles both by simply having a token
or not:

**Self-hosted** — a single trusted operator on loopback. No hosted sessions,
no machine identities. Construct the client with no `token`.

**Hosted** — a *machine identity* is created by an authenticated human wallet
session and is bound to that wallet's own x-only public key. A machine
credential (`pvmk_…`) is sent as `Authorization: Bearer`.

- A machine principal sees **exactly what its creating wallet could see, and
  never more** — every existing tenancy/covenant check applies to it
  unmodified. Foreign objects are `404`, not `403`: existence is hidden.
- **Scopes narrow further, and only further.** They gate which API
  *operations* a credential may attempt (`read:vaults`, `request:build`,
  `request:submit`, `governance:approve`, `risk:release`, …). They can never
  widen what tenancy already allows. Unmapped routes are **deny-by-default** —
  a route added later is unreachable by any machine identity until a human
  classifies it. Grant the smallest set that works;
  `client.capabilities().scopes` lists them with descriptions.
- `ownerPause` / `ownerRecover` additionally require `request:break-glass` on
  top of `request:build`. (An API-surface conservatism — the covenant's own
  owner-signature requirement is unaffected either way.)
- **Machine-identity management is wallet-session-only, structurally.** A
  token can never mint, widen, or revoke its own — or a sibling's —
  authority, at any scope. The `createIdentity` / `mintCredential` /
  `revokeIdentity` methods exist for operator tooling driving a wallet
  session; called with a Bearer token they refuse with
  `403 MACHINE_IDENTITY_ROUTE_FORBIDDEN`, by design.

### The token is never logged

The token is held in a module-private `WeakMap` keyed by the client instance,
**not** as a property of it. `console.log(client)`, `JSON.stringify(client)`,
`util.inspect(client)`, a heap dump, a stack trace, and every thrown error's
`.message` are all structurally incapable of containing it. This client also
has no logger and never writes to the console, so there is no verbosity
setting that could turn credential printing on. This is not redaction you
have to trust — the value is never in the string.

Rotate by minting a second credential, deploying it, then revoking the first.
Never revoke first. A minted token is shown **exactly once**; only its
SHA-256 is ever persisted server-side.

---

## Idempotency

Every mutating (`POST`) call carries an `Idempotency-Key`. If you do not
supply one, the client generates a fresh `pvsdk-<uuid>` per call.

The key comes back to you on **both** paths:

```js
const result = await client.createRequest(body);
result.idempotencyKey;          // non-enumerable: JSON.stringify(result) is still exactly the server's body
result.idempotency;             // { replayed: false, key } — the server's own marker

try {
  await client.createRequest(body);
} catch (err) {
  err.idempotencyKey;           // present on PolicyVaultApiError AND PolicyVaultNetworkError
}
```

Server semantics (`server/src/idempotency.js`): the first call with a key
executes exactly once; a retry with the **same** key and the **same** body
replays the original response verbatim (`idempotency.replayed: true`); the
same key with a *different* body is a deterministic `409
IDEMPOTENCY_KEY_CONFLICT` and the handler is never called; a genuine
concurrent duplicate gets `409 IDEMPOTENCY_IN_PROGRESS`. Keys are scoped per
identity — two callers can never collide or replay each other's keys.
Infrastructure failures (5xx) *release* the claim rather than poisoning the
key, so a retry gets a genuinely fresh attempt.

### Why there are no automatic retries

A client cannot distinguish "the request never arrived" from "the request
executed and the response was lost." A library-level retry of a mutating call
is therefore a library-level double-spend risk, and this client will not take
that decision on your behalf.

What it does instead is make **your** retry safe. Hold the key, decide to
retry, and reuse it:

```js
let key = randomIdempotencyKey();
for (let attempt = 0; attempt < 3; attempt++) {
  try {
    return await client.submitRequest(requestId, { idempotencyKey: key });
  } catch (err) {
    if (err instanceof PolicyVaultNetworkError) continue;  // same key: at-most-once still holds
    throw err;                                             // a server refusal is a decision, not a blip
  }
}
```

Pass `idempotencyKey: null` to send no key at all (byte-identical to a
pre-platform caller).

---

## Dry-run first

`client.simulate(body)` runs the **identical** pipeline the real call
would — governance classification, risk composition, planning, signer
authorization, the real transaction builder, real intent derivation and
verification — while persisting nothing, consuming no gate, and never
broadcasting. It is not a mock or an estimate; the fee, mass, and successor
it reports are exact.

Simulate first, always:

- It tells you *in advance* what the real call would still require —
  approvals, a governance proposal, a risk release — via `wouldRequire`,
  instead of you discovering it by consuming a gate.
- A well-formed body always answers `200` with `simulation.ok: true | false`.
  `ok: false` carries `refusalReason: { status, code, message }` — the exact
  refusal the real route would have produced. A **malformed** body is a real
  HTTP 4xx: a dry run answers "would this succeed", not "is this even
  well-formed".
- One honest gap, reported by the server itself as
  `vmPreflight: { skipped: true, reason }`: real preflight verifies a Schnorr
  signature over the frozen transaction, and a dry run has no signature to
  verify. Fee, mass, and successor correctness are still exact.

Simulation sends no idempotency key by default — there is nothing to make
idempotent, and spending a key on it would be misleading.

---

## Local verification — the part that matters

Everything above talks to a server. **This is the part that means you do not
have to trust one.**

The deterministic modules are the same code the server runs (re-exported, not
reimplemented — there is exactly one authoritative core). Run them yourself
and compare:

| You want to know | Use |
|---|---|
| Is this the state the covenant is actually bound to? | `vaultStateV4.normalizeStateV4` + `computeStateIdV4` |
| Is the successor they propose the one the covenant will accept? | `vaultTransitionsV4.agentSpendSuccessorV4` (etc.) — derive it yourself |
| Is this agent/recipient really in the committed set? | `agentMerkleV4.verifyAgentProofV4`, `recipientMerkleV3.verifyRecipientProof` — and recompute the root, never adopt one |
| Is this fee real? | `feeMass.computeMass`, `calculateRequiredFee` |
| Is this transaction the intent I asked for? | `intent.verifyIntentManifest` |
| What exactly am I endorsing with this approval? | `frozenTxV3.frozenTxCommitment`, `approvalPackageV4.assertPackageIntegrityV4` |
| What does this change, in words? | `explain.intentExplain`, `explain.governanceExplain` |

The strongest single check is the intent manifest:

```js
const { intent } = require("policyvault-sdk");

const verdict = intent.verifyIntentManifest({
  manifest,            // what the server says the transaction does
  requestedIntent,     // what YOU asked for — your own copy, never the server's
  decodedTransaction   // the actual bytes about to be signed
});

if (!verdict.ok) {
  // Do not sign. failures[] carries structured remediation codes.
  throw new Error(`intent refused: ${verdict.failures.map((f) => f.code).join(", ")}`);
}
verdict.statement; // "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE."
```

This is what lets a client detect a manipulated server or frontend **before**
a signature exists. Verify with *your* requested intent, held locally — a
manifest checked against a server-supplied "what you asked for" proves
nothing.

Unknown covenant versions **fail closed** everywhere. Nothing is routed to a
default handler, and a version you do not recognize is a refusal, not a
guess.

---

## Amounts: integer sompi, always

Every consensus and accounting value is **integer sompi** — BigInt in
JavaScript, a decimal **string** on the wire. `JSON.parse` would silently
destroy a u64 as an IEEE-754 double, so the client never coerces, rounds, or
"conveniently" converts an amount anywhere.

```js
const { parseSompi, kasToSompi, sompiToKas } = require("policyvault-sdk");

parseSompi("150000000");            // 150000000n
kasToSompi("1.5");                  // 150000000n   (max 8 fractional digits)
sompiToKas(150000000n);             // "1.5"

Number(simulation.review.feeSompi)  // NEVER. Not once. Not for display.
```

Note that different routes render amounts differently — the wallet/simulate
surfaces carry sompi (`feeSompi`) *and* KAS (`feeKas`) strings, while vault
presentation uses KAS strings (`protectedValueKas`). Both are strings; use
`parseSompi` on the sompi form and `kasToSompi` on the KAS form.

The parsers fail closed on `NaN`, `Infinity`, negatives, unsafe integers,
overflow, exponents, signs, and malformed decimals. Use them; do not write
your own.

---

## Errors

```js
const { PolicyVaultApiError, PolicyVaultNetworkError } = require("policyvault-sdk");

try {
  await client.submitRequest(requestId);
} catch (err) {
  if (err instanceof PolicyVaultApiError) {
    err.status;         // HTTP status, as sent
    err.code;           // e.g. "SCOPE_FORBIDDEN", "RISK_REVIEW_REQUIRED"
    err.serverMessage;  // the server's message, unmodified
    err.body;           // the full envelope, verbatim
    err.extra;          // route-specific siblings (request, idempotency, ...)
    err.idempotencyKey; // reuse to retry safely
  } else if (err instanceof PolicyVaultNetworkError) {
    // No answer arrived. You cannot know whether it executed —
    // replay err.idempotencyKey to find out safely.
  }
}
```

The client carries the server's `{ error: { code, message, ... } }` envelope
**verbatim**. It never maps one refusal code onto another, never upgrades a
refusal into a success, and never invents a code the server did not send. A
refusal you did not understand stays a refusal.

### Schema versions

The client stamps the `schemaVersion` it was written against onto the three
v0.4 bodies the server validates (`create`, `requests`, `simulate`). A server
speaking a different wire shape then answers a clean `422
SCHEMA_VERSION_UNSUPPORTED` instead of silently reinterpreting your body under
new semantics. That fail-closed behavior is the default on purpose; pass
`stampSchemaVersion: false` to omit the field (which is what the shipped web
client does).

---

## TypeScript

Hand-written declarations ship in `types/`. They are deliberately **not**
exhaustive: the flat surface and the client are typed precisely, while
response bodies and normalized state objects are typed as open records
wherever their single source of truth is the server or `core/model/*.js`.
A stale type asserting a field exists is worse than no type, so the
declarations decline to guess. Where the server stamps a `schemaVersion`,
pin *that* at runtime — it is the guarantee that actually holds.

---

## Not exported (and why)

The public entry point exports the deterministic, portable, offline-runnable
surface plus the client. Deliberately absent:

| Not exported | Why |
|---|---|
| `store`, `manifest*`, `audit`, `organization`, `reconcile*`, `durable-json`, `submission-claim`, `wallet-*` | Hosted/operator-side. Durable state and reconciliation truth are the server's business. |
| `chain`, `contract-compiler*`, `vault-builders*`, `create/spend/lifecycle/recover-vault` | Dial a node or spawn the `silverc` toolchain. Not portable, not offline, not an integrator's surface. |
| `config` | Reads `process.env` and the filesystem. Deployment configuration, not a library API. |
| `signer-dev`, `keys` | **TEST-ONLY** dev signer and key helpers. A published SDK must not offer a convenient path near key material. |
| `core/risk` | Platform orchestration around external adapters. Risk decisions are composed server-side; a client re-deciding them would be a second authority. |

These stay reachable in-repo by deep path
(`require("policyvault-sdk/src/<module>.js")`) — which is exactly how the
server and tools already use them. Nothing existing changes. They are simply
not advertised as a stable surface this SDK promises to keep.

---

## License

Apache-2.0. PolicyVault is **free forever, including commercial use** — the
protocol, covenant, SDK, API, and security features carry no fees,
subscriptions, paid tiers, usage caps, or paid security. Support is voluntary
(KAS donations / sponsorships / grants). PolicyVault seeks no patents over its
protocol, covenant, delegated-spending mechanisms, or SDK.
