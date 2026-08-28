# x402 Interoperability Adapter (surface 27)

**IMPLEMENTED + UNIT-TESTED + INTEGRATION-TESTED** (real spawned
PolicyVault server). Not testnet-verified through this adapter, not
production-hardened, not externally reviewed, not audited. **Not "x402
compatible"** in an ecosystem sense: no resource server, client SDK, or
facilitator supports Kaspa today, and no upstream Kaspa scheme exists.
This adapter interoperates only with servers explicitly configured to
accept the proposed Kaspa scheme.

Implements `docs/postlaunch/x402-adapter-spec.md`. PolicyVault plays the
**client / payer** role ONLY — never resource server, never facilitator,
and it NEVER emits an HTTP 402 of its own (free forever).

## Role and flow

x402 is HTTP-native: a resource server answers `402 Payment Required` with
a machine-readable `PAYMENT-REQUIRED`, and the client retries the identical
request carrying a signed payment payload. This adapter:

1. **[A] normalizes** the untrusted `PaymentRequired` into a closed
   PolicyVault intent (pure — refusals here are free);
2. runs the MANDATORY **dry run** (`POST /wallet/v4/simulate`);
3. asserts the x402 `exact` amount equality from the simulated review;
4. does the real **build** (`POST /wallet/v4/requests`) under a
   caller-`attemptId`-derived `Idempotency-Key`;
5. reports **pending** honestly (approvals / risk review / signature) or,
   once the request is `CHAIN_VERIFIED`, submits (behind the live-network
   gate) and only then;
6. **[G]** returns the `PAYMENT-SIGNATURE` retry material with the
   selected requirement echoed **byte-verbatim**.

Stages B–F are untouched existing PolicyVault surfaces reached over the
public Agent API. The adapter holds no key and signs nothing.

## Pay-first only

The Kaspa scheme MUST declare `extra.paymentFlow: "upfront"`. Kaspa has no
delegated-pull primitive and PolicyVault never emulates one; an
`authorization`-flow (or flow-absent) requirement is refused
`X402_FLOW_UNSUPPORTED`. Consequence: PolicyVault pays before receiving —
counterparty risk (not custody/consensus risk), bounded by the covenant's
cap/budget/allowlist/approval tier. A server that refuses after settlement
surfaces `X402_SERVER_REFUSED_AFTER_SETTLEMENT` for a human, never an
auto-retry.

## Configuration

```js
const { createX402Service } = require("integrations/x402/service");
const service = createX402Service({
  networkId: "testnet-10" | "mainnet",
  assetLiteral: "<agreed native-KAS sentinel>", // REQUIRED, no default (OQ-6)
  caip2NetworkId: "kaspa:testnet-10",            // interim, UNVERIFIED (OQ-5)
  rustyKaspaModule: "/path/to/rusty-kaspa/wasm/nodejs/kaspa",
  policyVault: { baseUrl: "http://127.0.0.1:8080", token: process.env.PV_X402_TOKEN },
  dataDir: "/var/lib/policyvault-x402"
});
service.listen(9402, "127.0.0.1");
```

The `token` is a `pvmk_` machine credential carrying EXACTLY the six
adapter scopes; supply it via the environment, never a file.

## Caller API (the adapter's own surface)

- `POST /x402/attempts` — `{ attemptId (UUID, MANDATORY), vaultId, agentPk,
  paymentRequiredHeader (base64) }`. The adapter never mints an
  `attemptId`. Same `attemptId` + same requirement digest replays; +
  different digest is a deterministic `409 IDEMPOTENCY_KEY_CONFLICT`.
- `POST /x402/attempts/:attemptId/delivery-result` — `{ delivered,
  paymentResponseHeader? }`. Records the resource server's post-settlement
  answer verbatim under `protocol.*`; a refusal-after-settlement escalates
  to a human.
- `GET /x402/attempts/:attemptId` — the stored attempt record.
- `GET /healthz`.

## Machine codes

Every refusal carries a machine code and a deterministic human explanation
(`x402/codes.js`; the G-1 lesson: a refusal nobody can read is an
availability bug). The set is closed.
