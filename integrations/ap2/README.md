# AP2 Interoperability Adapter (surface 28)

**IMPLEMENTED + UNIT-TESTED + INTEGRATION-TESTED** (real spawned
PolicyVault server). Not testnet-verified through this adapter, not
production-hardened, not externally reviewed, not audited. **Not "AP2
compatible"** in an ecosystem sense: no AP2 merchant, MPP, or
credential-provider implementation supports Kaspa today, and the non-ISO
currency token (below) will be rejected by strict validators. This adapter
interoperates only with counterparties explicitly configured to accept the
proposed Kaspa payment instrument.

Implements `docs/postlaunch/ap2-adapter-spec.md`. PolicyVault plays the
**Credential Provider** role (optionally Trusted Surface, not claimed
here) — never Shopping Agent, Merchant, Merchant Payment Processor, or
Network. It charges nothing and processes no one else's payments.

## Role and flow

AP2 is mandate-based: a user's authorization travels as cryptographically
signed, selectively-disclosable verifiable credentials (SD-JWT mandates).
The CP verifies inbound mandates and deterministically decides whether an
agent is authorized. This adapter:

1. **[A] verifies** the SD-JWTs — pinned `alg` (ES256) and `_sd_alg`
   (sha-256, absence refuses), pinned operator trust anchors (embedded
   `jwk`/`jku`/`x5u` key material refused), disclosure-digest binding,
   mandatory KB-JWT key binding, `exp`/`iat`, `checkout_hash`. **A
   verification PASS proves authorship, NOT authorization.**
2. **[B] normalizes** the closed schema and extracts **restrictive-only**
   constraints;
3. resolves the destination **PolicyVault-side** (`payee.id` -> operator
   payee directory -> x-only key that MUST already be covenant-allowlisted
   — `payee.name`/`website` never influence resolution);
4. evaluates constraints (deny-wins; unknown/unparseable = DENY);
5. runs the MANDATORY dry run, then the real build under a
   `transaction_id`-derived `Idempotency-Key`;
6. reports mandate rejection / pending / — only on `CHAIN_VERIFIED` —
   settlement evidence. **No pull credential is ever issued** (§6.4:
   pay-first, on-chain settlement in place of a redeemable token).

## The mandate-signature fallacy

A valid user signature over "up to 500 KAS to anyone" grants the agent
**zero** additional PolicyVault authority. The covenant's `maxPerSpend`,
`periodBudget`, `agentRecipientRoot`, `approvalThreshold`, and `paused`
flag are enforced by Kaspa consensus; no off-chain credential can raise
any of them. An open mandate is a ceiling the user may lower, never a
floor they may raise — the floor never moves.

## Configuration

```js
const { createAp2Service } = require("integrations/ap2/service");
const service = createAp2Service({
  networkId: "testnet-10" | "mainnet",
  rustyKaspaModule: "/path/to/rusty-kaspa/wasm/nodejs/kaspa",
  policyVault: { baseUrl: "http://127.0.0.1:8080", token: process.env.PV_AP2_TOKEN },
  dataDir: "/var/lib/policyvault-ap2",
  trustAnchors: { "<kid>": { jwk: { kty:"EC", crv:"P-256", x, y }, role: "user"|"agent" } },
  instruments: { "<opaque handle>": { vaultId, agentPk } },
  payeeDirectoryFile: "/etc/policyvault/payees.json", // or `payeeDirectory: {...}`
  instrumentType: "org.policy-vault.kaspa.covenant-vault.v1", // interim (OQ-9)
  currencyLiteral: "KAS",  // non-ISO; DEVIATES from AP2's ISO-4217 text (OQ-4)
  requiredConstraintTypes: ["payment.amount_range","payment.budget","payment.allowed_payees"]
});
```

`trustAnchors` is deployment configuration; **unconfigured, every
verification fails closed** (`AP2_TRUST_ANCHOR_UNCONFIGURED`). The payee
directory is a closed-schema map resolved through the authoritative
address parser at startup.

## Caller API (non-normative — AP2 specifies no CP transport)

- `POST /ap2/payment-mandates` — `{ paymentMandate, checkoutMandate?,
  openPaymentMandate?, openCheckoutMandate?, expectedNonce? }` (compact
  SD-JWTs).
- `GET /ap2/attempts/:transactionId`, `GET /healthz`.

## Interim decisions

Currency (`"KAS"`, non-ISO), instrument type, CAIP-style ids, DAA-score
omission, receipt schema (not invented), and the adapter-side constraint
homing (v1) are all recorded in
`docs/postlaunch/x402-ap2-implementation-evidence.md`. No upstream
registration or ecosystem compatibility is claimed.
