# KasWare → Universal Signer Interface v1 — mapping of the EXISTING flow

Status: **DESIGNED** (analysis document). It maps the shipped
production KasWare integration onto the Universal Signer Interface v1
(`docs/postlaunch/signer-interface-spec.md`, `core/signer/`) **without
changing it** — `web/wallet.js`, `web/app.js`, `web/app-v4.js`,
`server/src/auth.js` are read-only sources here and remain the
production path. No KasWare USI adapter is implemented yet (that would
live in the browser layer; `core/signer` is DOM-free); this document is
the evidence that the interface can express the real flow exactly.

Sources read (private tree, commit `3db4759` worktree):

- `web/wallet.js` — `KasWareAdapter` (the existing generic
  `WalletAdapter` surface), `WalletError`, `normalizePublicKeyToXOnly`,
  `normalizeNetwork`.
- `web/app.js` — canonical wallet session, `connectWith`,
  `verifyNetwork`, hosted sign-in (`hostedSignIn`), wallet-change
  security events.
- `web/app-v4.js` — `assertCanonicalSignInputs`, `walletSign` (stages
  B–K), `completeRequestFlow`, `approve`.
- `server/src/auth.js` — `HostedAuthService` (`challengeText`,
  `createChallenge`, `verify`), `AuthErrorCodes`.
- `sdk/src/address-identity.js` — the ONE address→x-only boundary
  (PubKey-version-only, network-family gate).
- `sdk/src/wallet-submit-v4.js` — frozen-txid enforcement
  (`TXID_MISMATCH`).
- `docs/hosted-architecture.md` §7 — the KasWare source finding
  (2026-08-23): `kasware.signMessage` is a **verbatim pass-through** to
  kaspa-wasm `signMessage` (Schnorr for normal keyrings; ECDSA only for
  the Tangem hardware address type; callers may force
  `type: "schnorr"`), and personal messages live in the
  `PersonalMessageSigningHash` domain, structurally separated from
  `TransactionSigningHash`.

---

## 1. Capability descriptor KasWare declares under USI v1

```json
{
  "interfaceVersion": "policyvault-signer/1",
  "provider": "kasware",
  "label": "KasWare",
  "kind": "browser-extension",
  "schemes": ["schnorr"],
  "networks": ["mainnet", "testnet-10"],
  "features": {
    "messageSigning": true,
    "transactionSigning": true,
    "specificInputSigning": true,
    "multiAccount": false,
    "networkSwitching": false,
    "accountEvents": true,
    "asynchronousApproval": false,
    "airGapped": false,
    "hardwareDisplay": false
  }
}
```

Justification against the real adapter (`web/wallet.js`
`KasWareAdapter.getCapabilities()` plus behavior):

| USI declaration | Existing evidence |
| --- | --- |
| `schemes: ["schnorr"]` | The adapter FORCES `{ type: "schnorr" }` in `signAuthMessage` (wallet.js:199) and validates a 128-hex (64-byte BIP-340) result (wallet.js:206). It never requests ECDSA. The descriptor describes what the ADAPTER offers upward — KasWare-the-extension can produce ECDSA for Tangem accounts, but this adapter never exposes that path, so declaring `schnorr` only is the truthful contract. |
| `networks: ["mainnet","testnet-10"]` | `normalizeNetwork` (wallet.js:73–80) canonicalizes provider labels to exactly these two ids; anything else is left non-canonical and fails the app's network gate. |
| `messageSigning: true` | `signAuthMessage` via `kw.signMessage` (wallet.js:192–210). |
| `transactionSigning: true` + `specificInputSigning: true` | `signInputs(unsignedSafeJson, signInputs)` via `kw.signPskt({ txJsonString, options: { signInputs } })` (wallet.js:245–263) — KasWare signs exactly the named inputs of the frozen Safe JSON (`canSignSpecificInputs: true` in the legacy capability object, wallet.js:101–107). |
| `multiAccount: false` | `connect()` takes `accounts[0]` only (wallet.js:123); no account-selection surface. |
| `networkSwitching: false` | Legacy `canSwitchNetwork: false` (wallet.js:104); the app never switches programmatically — the human switches inside the wallet and the server's configured network stays authoritative (app.js `verifyNetwork`, 106–131). |
| `accountEvents: true` | `kw.on("accountsChanged"/"networkChanged")` subscription (wallet.js:227–240). |
| `asynchronousApproval: false` | The extension popup resolves the same in-page promise; no out-of-band approval channel. (Consequence under USI: no `cancelSigning` required, `timeoutMs` optional.) |

## 2. Method mapping

| USI v1 method | Existing KasWare adapter member (web/wallet.js) |
| --- | --- |
| `describe()` | NEW (constant object above). Legacy `getCapabilities()` (99–108) carries the same facts in the old key names. |
| `detect()` | `detect()` (96–98) — `!!window.kasware`. |
| `connect()` | `connect()` (109–131) — `kw.requestAccounts()`, then `getNetwork` normalization, then event subscription; rejection classified `USER_REJECTED` on `e.code === 4001 || /reject/i` (115–117). |
| `disconnect()` | `disconnect()` (132–141) — best-effort `kw.disconnect(window.location.origin)`. |
| `getActiveAccount()` | `getActiveAddress()` (153–155), reshaped to `{ address } \| null`. |
| `getNetwork()` | `getNetwork()` (156–159) — live `kw.getNetwork()` through `normalizeNetwork`. |
| `getPublicKey()` | `getPublicKeyRaw()` (213–223) — the provider-native 66-hex compressed key used by the auth verify call. The x-only form is DERIVED, not a second provider call: core `normalizePublicKeyToXOnly` is the byte-exact port of wallet.js:57–70 (64-hex pass, 02/03 → X, 04 refused, shape-only diagnostics), so `getPublicKeyXOnly()` (167–183) ≡ `normalizePublicKeyToXOnly(await getPublicKey(), "KasWare")`. |
| `on(event, cb)` | `on()` + `_subscribe()` (224–240) — `accountsChanged` → `accountChanged`, `networkChanged` → `networkChanged`. |
| `signMessage(request)` | `signAuthMessage(message)` (192–210) — `kw.signMessage(request.message, { type: "schnorr" })`; result gate `/^[0-9a-f]{128}$/i` ≡ core `validateSignatureResponse` for schnorr. |
| `signTransaction(request)` | `signInputs(unsignedSafeJson, signInputs)` (245–263) — `kw.signPskt({ txJsonString: request.unsignedSafeJson, options: { signInputs: request.signInputs } })`; non-empty-string result gate ≡ core `validateSignedTransactionResponse`. |
| `cancelSigning` | NOT required (asynchronousApproval false) — and KasWare exposes no cancellation API. |

Adapter-side error classification (the sanctioned `signerCode` channel,
descendant of `walletCategory`):

| Existing `WalletError` (wallet.js:15–25) | USI `SignerErrorCodes` |
| --- | --- |
| `WALLET_NOT_FOUND` | `SIGNER_NOT_FOUND` |
| `WALLET_DISCONNECTED` | `SIGNER_DISCONNECTED` |
| `USER_REJECTED` (4001 / `/reject\|denied/i` heuristics stay in the adapter) | `USER_REJECTED` |
| `WRONG_NETWORK` | `WRONG_NETWORK` |
| `ACCOUNT_CHANGED` | `ACCOUNT_CHANGED` |
| `SIGNING_UNSUPPORTED` (provider lacks `signMessage`/`signPskt`) | `UNSUPPORTED_CAPABILITY` |
| `INVALID_SIGNATURE_RESPONSE` | `INVALID_SIGNATURE_RESPONSE` |
| `INVALID_PUBLIC_KEY` | `INVALID_PUBLIC_KEY` |
| `PROVIDER_ERROR` | `PROVIDER_ERROR` |
| — (new) | `SIGNER_LOCKED`, `SIGNER_TIMEOUT`, `UNSUPPORTED_SCHEME`, `PROTOCOL_VIOLATION`, `INTERFACE_VERSION_UNSUPPORTED`, `REQUEST_INVALID` |

Every legacy category maps 1:1 onto the closed v1 taxonomy; the new
codes cover surfaces the old boundary could not express (locking,
deadlines, scheme negotiation, contract breaches, versioning). An
adapter emitting anything outside the taxonomy is mapped fail-closed to
`PROTOCOL_VIOLATION` by `normalizeAdapterFailure` — the USI equivalent
of "no unknown category may pass".

## 3. Hosted sign-in flow (app.js `hostedSignIn`, 265–302) under USI

1. **Challenge issuance (server, unchanged):** `POST /auth/challenge` →
   `HostedAuthService.createChallenge` (auth.js:338–379). The wallet
   address passes `resolveAddressIdentity`
   (sdk/src/address-identity.js): canonical form, correct network
   FAMILY prefix, and **PubKey (Schnorr x-only) address version only —
   ECDSA/Tangem and script-hash accounts fail HERE** with
   `AUTH_ACCOUNT_TYPE_UNSUPPORTED` (auth.js:343–345,
   `ECDSA_UNSUPPORTED_MESSAGE` 75–77) *before any signing round-trip*.
   The challenge text is the frozen 7-line server-built message
   (`challengeText`, auth.js:319–329) ending "This signature only signs
   you in. It cannot move funds."
2. **Signature:** `ui.adapter.signAuthMessage(challenge.message)`
   (app.js:277) becomes
   `executeSigning(kaswareRegistration, createMessageSigningRequest({
   message: challenge.message, scheme: "schnorr", network:
   serverNetwork, expectedSignerAddress: forAddress }), ...)`.
   - Schnorr-only enforcement point 1 (client): the explicit
     `scheme: "schnorr"` request field ≡ the forced
     `{ type: "schnorr" }` (wallet.js:199 — never "auto", which could
     silently change the scheme on Tangem-class accounts).
   - The manual mid-flow guard "wallet may have switched" (app.js:280–283)
     is SUBSUMED by the interface's pre/post identity gates and live
     network gate — the same refusals, now uniform for every adapter.
3. **Public key claim:** `getPublicKeyRaw()` (app.js:284) ≡
   `adapter.getPublicKey()`.
4. **Verification (server, unchanged) — this is the identity-proof
   rule executed:** `POST /auth/verify` →
   `HostedAuthService.verify` (auth.js:391–454), fail-closed order:
   - shape gates — nonce 64-hex; **signature `/^[0-9a-f]{128}$/`
     (Schnorr-only enforcement point 2: the length gate admits only
     64-byte BIP-340; "no silent retry as another signature type",
     auth.js:395–399)**; pubkey 64-hex x-only or 66-hex compressed;
   - atomic single-use challenge claim (store CAS);
   - challenge↔wallet and challenge↔server **network binding
     (`AUTH_NETWORK_MISMATCH` — network mismatches fail closed)**;
   - pubkey→x-only via kaspa-wasm and **lossless identity binding**:
     the submitted key must equal exactly the key inside the
     challenge's wallet address (auth.js:421–432);
   - Schnorr verification of the **server-reconstructed** message —
     "the ONLY message verified" (auth.js:434–443,
     `kaspa.verifyMessage`); a client-submitted message string is never
     accepted.
   Only after all of that does a session exist — i.e. the
   provider-claimed identity (address + pubkey from the adapter) was
   never trusted; it was PROVEN by signature over a server-issued
   challenge, exactly the interface-contract rule (spec §6). Domain
   separation (`PersonalMessageSigningHash` vs
   `TransactionSigningHash`, hosted-architecture.md §7) guarantees the
   auth signature can never be replayed as covenant authority.
5. **Session invalidation on identity change:** app.js:314–327 treats
   account/network switches as security events. Under USI these arrive
   through the adapter's `accountChanged`/`networkChanged` events —
   same wiring, provider-independent.

## 4. Frozen-transaction signing flow (app-v4.js) under USI

Existing `walletSign(unsignedSafeJson, signInputsList, expectedSigner)`
(app-v4.js:139–164) with stages B–K, and `approve(req)` (251–270) which
signs ONLY the covenant input of the exact frozen transaction:

| walletSign stage (app-v4.js) | USI equivalent |
| --- | --- |
| B entered / C expected signer resolved (146: connected wallet must BE the expected signer) | `createTransactionSigningRequest` REQUIRES `expectedSignerAddress`; `executeSigning` pre-invocation identity gate (`SIGNER_DISCONNECTED` / `ACCOUNT_CHANGED`). |
| D canonical signInputs validated (`assertCanonicalSignInputs`, 106–115: `{ index, sighashType: 1 }` only — the real-KasWare `sighashTypes:[undefined]` incident guard) | Byte-exact port in core `assertCanonicalSignInputs`, run at request creation AND re-run inside `executeSigning`; entries additionally refuse unknown extra keys. |
| E provider signPskt invoked | `SUBMITTED` transition; `adapter.signTransaction(request)`. |
| F returned / G returned shape checked (152) | `validateSignedTransactionResponse` (non-empty string, returned VERBATIM). |
| I post-popup signer re-verified (154–158: "refusing to submit a signature from a different identity") | Post-approval identity re-check against `expectedSignerAddress` → `ACCOUNT_CHANGED`, signature discarded. |
| K returned to caller | Frozen `{ requestId, status: "approved", result: { signedSafeJson } }`. |
| Stage diagnostics (`walletStageError`, 120–129) | `onTransition` frozen lifecycle records + `SignerError.cause` preservation (original name/message kept; never logs secret material). |
| H/J server-side PSKT decode + signature extraction; frozen-txid rule | UNCHANGED and outside the interface by design: the SDK finalizer re-derives the txid from the frozen serialization and refuses drift (`sdk/src/wallet-submit-v4.js:215` "reconstructed txid != frozen txid — refusing to broadcast"; genesis path :496). "PolicyVault never reconstructs different bytes after signature." |

The approver flow (`approve`, app-v4.js:251–270) is expressed as a
transaction request whose `signInputs` is exactly the ONE canonical
covenant-input entry from the durable frozen request — the same bytes
every other approver and the agent sign; the server independently
verifies the signature against the connected approver's identity.
Nothing about that changes: the interface transports the same frozen
entries verbatim.

`completeRequestFlow` (app-v4.js:203–220) and the durable request state
machine (BUILD → AWAITING_APPROVALS → … → CHAIN_VERIFIED) sit ABOVE
the interface, unchanged: builders never broadcast, the signer never
finalizes, and only server/SDK chain verification advances state.

## 5. Where Schnorr-only is enforced / where ECDSA (Tangem) is refused

1. **Challenge issuance** — `resolveAddressIdentity` admits only
   PubKey-version (32-byte Schnorr x-only) addresses; `PubKeyECDSA` and
   `ScriptHash` versions fail closed with
   `AUTH_ACCOUNT_TYPE_UNSUPPORTED` before any wallet popup
   (auth.js:338–347; address-identity.js header contract).
2. **Client signing request** — the adapter forces
   `{ type: "schnorr" }` (wallet.js:199); USI: explicit
   `scheme: "schnorr"`, and `executeSigning` refuses any sign-message
   scheme without a v1 response contract BEFORE invoking the signer.
3. **Client response gate** — 128-hex check (wallet.js:206) ≡ core
   schnorr response contract.
4. **Server verify shape gate** — `SCHNORR_SIG_HEX` 128-hex only; "the
   length-gate enforces the Schnorr scheme … no silent retry as another
   signature type" (auth.js:395–399).
5. **USI negotiation (new, additive)** — a consumer requiring
   `schemes: ["schnorr"]` structurally refuses an ecdsa-only adapter
   with `UNSUPPORTED_SCHEME` (UNIT-TESTED `negotiation.test.js`),
   moving the refusal to the earliest possible moment: before an
   adapter is even selected.

## 6. Behaviors the interface cannot yet express (honest gaps)

1. **Silent session resume** — `KasWareAdapter.reconnect()`
   (wallet.js:142–152) resumes via `kw.getAccounts()` without a consent
   popup. USI v1 has `connect()`/`disconnect()` only; a KasWare USI
   adapter would fold resume into `connect()` (prompt-free when already
   authorized), but "resume-only, never prompt" is not expressible as a
   distinct contract yet.
2. **Legacy capability key `canReturnRawSignedTx`** (wallet.js:103) has
   no USI equivalent; no funds-critical consumer reads it today.
3. **UI wallet-state machine** — `WalletState`
   (NOT_DETECTED…READY, wallet.js:34–42; driven by app.js
   `verifyNetwork`) is presentation-layer state ABOVE the interface;
   USI deliberately does not model UI states (derivable from
   detect/connect/getNetwork + events + refusal codes).
4. **Event unsubscription** — neither the existing adapters nor USI v1
   define `off()`; listener lifecycle is a v2 candidate (spec §13.7).
5. **Origin-scoped disconnect** — `kw.disconnect(window.location.origin)`
   (wallet.js:135) is adapter-internal; USI passes no origin (correct
   for non-browser signers, but the browser adapter must supply it
   itself).
6. **Locked-state detection** — KasWare exposes no distinct "locked"
   signal to this flow (`SIGNER_LOCKED` exists in the taxonomy for
   providers that do report it; a KasWare adapter would keep mapping
   such failures to `PROVIDER_ERROR`/`USER_REJECTED` per observed
   behavior).
7. **Public-key diagnostic log** — `getPublicKeyXOnly` logs the
   public-key normalization (wallet.js:179–181, public material only);
   `core/signer` performs no logging by design — if that diagnostic is
   still wanted it moves to the adapter/UI layer.
8. **ECDSA/Tangem support** — not expressible END-TO-END on purpose:
   declarable and refusable (negotiation), but unsignable (no v1
   response contract; hosted auth v1 refuses the account type). Same
   product posture as today, now structural (spec §13.1).

## 7. Conclusion

Every funds-relevant behavior of the shipped KasWare + hosted-auth flow
— connection, account/network discovery and their security events, the
Schnorr-forced challenge signature, the raw-pubkey claim, the
server-side identity PROOF, the canonical frozen signInputs, the exact
frozen-bytes signing contract, the pre/post identity re-checks, and
every error category — maps 1:1 onto Universal Signer Interface v1,
with the gaps limited to non-funds conveniences (§6) that stay in the
adapter or UI layer. The interface therefore removes the architectural
KasWare dependence while changing zero production bytes.
