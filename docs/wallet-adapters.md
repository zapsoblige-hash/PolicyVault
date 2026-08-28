# PolicyVault Wallet Adapters

How the browser signing architecture works and how to add a wallet.

## Architecture

```
PolicyVault UI (web/app.js)
    | generic contract only — no KasWare branches in funds logic
    v
WalletAdapter (web/wallet.js)
    +-- KasWareAdapter        (first real browser wallet)
    +-- MockAdapter           (architecture test; gated dev-sign endpoint)
    +-- [future adapters]
Headless signer sources (sdk):
    +-- makeDevSigner         (TEST-ONLY, testnet)
    +-- agent-sdk external signer (extension point)

All converge on the canonical signer contract:
    signInputs(unsignedTxSafeJson, signInputs[]) -> signedTxSafeJson

and feed the SAME hardened pipeline:
    buildWalletRequestV2 / buildCreateWalletRequestV2  (server, no key)
    -> wallet signs the named inputs
    -> attachWalletSignatureV2: signed-package immutability validation,
       covenant-signature extraction + re-embed via pv_call_encoder,
       exact-fee preservation, preflight, durable claims, submit,
       exact chain proof, manifest advancement
```

No adapter is the funds-security boundary; Kaspa consensus is. Adapters
supply authorization material only. The exact fee is fixed at BUILD time
from the known final signature-script lengths, so the wallet signs once.

## Adapter contract (all methods required)

`detect()`, `connect()`, `disconnect()`, `reconnect()`,
`getActiveAddress()`, `getNetwork()` (canonical `testnet-10`/`mainnet`),
`getCapabilities()`, `getPublicKeyXOnly()`, `on("account"|"network", cb)`,
`signInputs(unsignedSafeJson, signInputs) -> signedSafeJson`.

Capabilities: `canSignTransaction`, `canSignSpecificInputs`,
`canReturnRawSignedTx`, `canSwitchNetwork`, `canExposeXOnlyPubkey`,
`supportsAccountChangeEvents`. Fail closed when a required capability is
missing (`SIGNING_UNSUPPORTED`).

Errors normalize to: `WALLET_NOT_FOUND`, `WALLET_DISCONNECTED`,
`USER_REJECTED`, `WRONG_NETWORK`, `ACCOUNT_CHANGED`,
`SIGNING_UNSUPPORTED`, `INVALID_SIGNATURE_RESPONSE`,
`INVALID_PUBLIC_KEY`, `PROVIDER_ERROR`. Funds logic never branches on
provider-specific error strings.

## Connected-wallet identity (owner pubkey)

`getPublicKeyXOnly()` returns the connected account's public key as
canonical 32-byte lowercase x-only hex. Providers differ in wire format —
KasWare's `getPublicKey()` returns the 33-byte compressed secp256k1 key
(66 hex chars, `02`/`03` parity byte + X coordinate; vendor-documented).
Every adapter routes the raw provider value through the ONE shared
normalizer, `normalizePublicKeyToXOnly` (exported from `web/wallet.js`):

- 64-hex x-only → canonicalized (trim, lowercase — same rule as the SDK's
  `normalizeHex`);
- 66-hex compressed `02`/`03` + X → X;
- everything else fails closed with `INVALID_PUBLIC_KEY`: missing value,
  non-hex, wrong length, uncompressed `04` keys, malformed provider
  responses. Error messages carry only the value's shape.

Dropping the parity byte is the canonical compressed→x-only mapping
(Kaspa P2PK addresses encode the x-only key; BIP340 signing handles Y
parity), and it is the same relationship the SDK already uses in reverse
(`new PublicKey("02" + xonly)` for address derivation).

The dashboard derives the create-vault OWNER from
`getPublicKeyXOnly()` at submit time — users never type or edit their
connected wallet's public key, and the form's owner field is display
only. Downstream validation (`normalizeTemplateV2`) stays strict
64-hex x-only: normalization happens at this adapter boundary and
nowhere else (the create API rejects raw compressed owners with
`COMPRESSED_OWNER_PUBKEY` as a diagnostic, without normalizing).

## Address-based UX (normal users never see pubkeys)

PolicyVault accepts normal Kaspa wallet addresses in the UI and derives
the exact public-key representation required by the covenant internally.

- OWNER shows as the connected wallet's address; internally the adapter
  pubkey is normalized to x-only and cross-checked against the connected
  address's payload (mismatch fails closed — account-switch race).
- DELEGATE and ALLOWED RECIPIENTS are entered as `kaspatest:` addresses.
- Conversion happens in ONE place: `sdk/src/address-identity.js`
  (`resolveAddressIdentity`), backed exclusively by the authoritative
  rusty-kaspa WASM parser (`Address` + `XOnlyPublicKey`); the browser
  does no address decoding — it calls `POST /identity/resolve-address`
  (see `web/identity.js`).
- Only version `PubKey` addresses (32-byte Schnorr x-only payload) are
  supported, for every role. This is the only type with a lossless
  address ⇄ pubkey mapping: the covenant authorizes owner/delegate with
  direct Schnorr pubkeys and pays recipients via
  `ScriptPubKeyP2PK(x-only)`.
- Intentionally unsupported, fail-closed: `ScriptHash` addresses (a
  script hash contains no recoverable pubkey), `PubKeyECDSA` addresses
  (33-byte key for the ECDSA path; the covenant uses Schnorr), and any
  unknown future address version. Also rejected: malformed addresses,
  checksum failures, wrong network family, empty/non-string input. The
  resolver additionally round-trips the derived key back to the same
  address, so nothing is ever guessed, hashed, or synthesized.
- The address prefix identifies only the network FAMILY (`kaspa` /
  `kaspatest`) — it cannot distinguish testnet-10 from testnet-11. The
  wallet==server==testnet-10 runtime verification remains authoritative;
  address parsing is an additional gate, never a replacement.
- Errors at this boundary are user-facing ("Enter a valid Kaspa wallet
  address.", "That address is not valid for the current network…") — the
  strict 32-byte-hex errors remain for internal/programmatic APIs.
- An "Advanced details" disclosure shows the derived x-only identities
  read-only; normal use never requires them, and no user is ever taught
  to strip `02`/`03` prefixes.

## Signature return format

The adapter returns the SAME transaction Safe JSON with each requested
input's `signatureScript` set (ordinary push of the 65-byte Schnorr
signature — KasWare `signPskt` semantics). The server-side finalizer:

1. verifies every consensus-visible field is byte-identical to the built
   request (only input signature scripts may differ);
2. extracts the covenant input's 65-byte signature and re-embeds it in the
   covenant call via `pv_call_encoder`; ordinary inputs keep the wallet's
   signature script;
3. re-verifies the exact fee, preflights, claims, submits, and requires
   exact chain proof before `CHAIN_VERIFIED`.

The wallet UI must never treat `SUBMITTED` as success.

## Network handling

Live operations are testnet-10 only. The UI verifies the wallet network
against the server network on connect and on every network-change event;
mismatch = `WRONG NETWORK`, signing controls disabled, in-progress
requests discarded (never silently retargeted). A network switch must be
re-read and re-verified before build/sign. Mainnet stays disabled.

## Account / stale handling

An account change discards any in-progress request (`ACCOUNT_CHANGED`);
an old signature is never reinterpreted for a new account (the request
records `signerAddress` and the UI refuses to sign from a different
account; the finalizer's state binding rejects stale requests with
`STALE` after any vault advance).

## Reload / recovery

The browser stores convenience state only (preferred provider, labels).
Chain state, request status, claims and manifests live in the durable
backend; the page re-reads them after reload (`GET /vaults`,
`GET /wallet/requests/:id`).

## v0.1 vaults

The dashboard shows v0.1 vaults read-only with the proven upgrade path
(owner recover → create v0.2). Unknown versions fail closed with
controls disabled.

## Adding a new wallet provider

1. Implement one adapter class in `web/wallet.js` satisfying the contract
   above (including error normalization and capability metadata).
2. Add provider-specific tests alongside the generic contract tests in
   `sdk/test/wallet-adapter.test.js` (fake only the provider global).
3. Run the full flow against testnet with the new adapter and record
   manual compatibility evidence in `docs/testnet-evidence.md`.

The production-byte rule applies: adapters must not construct or modify
consensus-visible bytes — if a new browser component ever does, it needs
an integration test that sends its exact output through the real
downstream validator.

## Test-only components

- `sdk/src/signer-dev.js` — deterministic signer fixture (testnet only).
- `/api/v1/wallet/dev-accounts`, `/api/v1/wallet/dev-sign` — gated by
  `POLICYVAULT_DEV_SIGNER=1` AND non-mainnet; used by the MockAdapter for
  the §17 architecture test and the automated e2e. Never enable in
  production.

## Remaining limitations

- ~~Real-KasWare manual lifecycle pending~~ — **MANUALLY VERIFIED
  2026-08-16**: the full v0.2 lifecycle, including Close Vault & Withdraw
  and a reconciliation / Verify Vault State scenario, was executed by the
  user with a real KasWare wallet (`docs/testnet-evidence.md` "Vault 5").
- Rollover spends (`rolloverAndSpend`) are exposed via the API but not
  yet surfaced as a dashboard control.
- One fuel UTXO per operation is selected; consolidation UX is future
  work.

## Checkpoint G (2026-08-19) — v0.4 owner / agent / approver signing

The v0.4 integration reuses the exact wallet-adapter contract as v0.2:
`signInputs(unsignedSafeJson, signInputs)` → signed Safe JSON, which maps to
KasWare `signPskt({ txJsonString, options: { signInputs } })`. For v0.4:

- **Owner** operations and **agent** spends: the wallet signs the covenant
  input (index 0) — and the ordinary fuel input (index 1) when present — with
  SIG_HASH_ALL. The server extracts input 0's 65-byte Schnorr signature and
  embeds it in the covenant call; the fuel input keeps its ordinary signature
  script.
- **Approver** signing (above-threshold agent spends): an approver is NOT a
  transaction input signer, but the covenant checks each approval as a
  SIG_HASH_ALL Schnorr signature over the covenant INPUT's sighash (input 0).
  KasWare CAN produce exactly this via `signPskt({ signInputs: [{ index: 0,
  sighashType: 1 }] })` — the approver signs the same frozen transaction's
  input 0, and the server extracts the 65-byte signature into the fixed
  approver slot. No `signMessage` / wallet-specific message signature is used
  or accepted (it would not be the exact transaction sighash and is therefore
  unusable for covenant approval). This is the standard, supported path — no
  export/import fallback is required, though the frozen approval package is
  fully serializable and supports an out-of-band collection flow if desired.

The dev/mock adapter (`sdk/src/signer-dev.js`, `web/wallet.js` MockAdapter)
mirrors this contract byte-for-byte and drives the automated
production-byte HTTP→VM integration tests (`sdk/test/api-v4.test.js`,
`sdk/test/wallet-requests-v4.test.js`). The browser is untrusted presentation;
the server independently enforces authorization and derives every
security-visible field.
