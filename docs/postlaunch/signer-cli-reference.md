# PolicyVault CLI keyfile signer — reference adapter (signer independence proof)

Status: **DESIGNED + IMPLEMENTED + UNIT-TESTED** (post-launch upgrade
program, COMPLETION_STANDARD requirement 4 "Signer independence").
Implementation `core/signer/adapters/cli/` (adapter.js, cli.js), suites
`core/signer/adapters/cli/test/` — `node --test`, 65/65, alongside the
untouched v1 core suite (`core/signer/test/`, 88/88; combined `core/`
tree 317/317). Nothing here is TESTNET-VERIFIED or PRODUCTION-HARDENED,
and no production flow has been migrated onto it: the shipped production
signing path (KasWare through `web/wallet.js` + hosted auth) is
unchanged.

## 1. What it is — and what it proves

The first **materially different** reference signer behind the Universal
Signer Interface v1 (`docs/postlaunch/signer-interface-spec.md`): an
OFFLINE, headless, operator-run local-keyfile signer (`kind: "cli"`),
built with real cryptography (vendored rusty-kaspa kaspa-wasm — BIP-340
Schnorr in Kaspa's `PersonalMessageSigningHash` /
`TransactionSigningHash` domains), where KasWare is a browser extension
with an injected provider and human per-signature prompts.

It proves, with executable evidence rather than argument, that the
interface is not shaped around KasWare:

| Axis | KasWare (production) | CLI keyfile signer (this adapter) |
|---|---|---|
| Host | browser page, injected `window.kasware` | headless Node process, no DOM |
| Consent | human clicks per request | operator invocation of the command IS the approval |
| Key custody | extension keyring | operator's local keyfile (mode 600) |
| Transport | in-page provider calls | local files in / JSON out; **no network I/O at all** |
| Discovery | provider injection | keyfile presence (`detect()`) |
| Events / multi-account | yes | none (declared `false`, refused by negotiation when required) |

Both adapters pass the SAME v1 gates: `validateAdapter`, registry
registration, capability negotiation, and the full `executeSigning`
lifecycle with its capability / scheme / network / identity fail-closed
gates (`core/signer/adapters/cli/test/conformance.test.js`).

## 2. Custody & threat model

**Signers custody keys — that is their role.** The keyfile belongs to
the signer's OPERATOR (a human at a workstation, a CI-less ops box, an
air-gapped laptop shuttling files). PolicyVault-the-service never sees
it: the adapter's outward surface is exactly the v1 interface — claims
(address / public key / network) in, signatures out — and the interface
has no vocabulary through which secret material could travel (spec §3).

- The keyfile is created only by the adapter's own `generate` helper
  (kaspa-wasm `Keypair.random()` — never a homemade scheme, never a
  seed phrase; the adapter refuses seed phrases structurally by having
  no input that accepts one).
- File mode 600 is enforced twice: at creation (`O_EXCL` + mode 0600 +
  post-write chmod) and at EVERY load — a group/other-readable keyfile
  is refused fail-closed with a `chmod 600` instruction.
- Every load re-derives the public key and address from the private key
  and refuses the file if its stored identity claims disagree (tamper
  detection; stored claims are never trusted).
- Secret material never appears in stdout, stderr, error messages
  (shape-only diagnostics), or returned identities — enforced by the
  no-secret-in-output scan over every CLI interaction of the test
  session (`cli.test.js`).
- Trust boundary honestly stated: **whoever reads the keyfile IS the
  signer.** An attacker with the file holds the delegate/owner key it
  contains, exactly as an attacker holding a KasWare seed does. The
  protections that matter against a compromised key remain where they
  always were — the covenant's consensus-enforced limits. This adapter
  adds custody hygiene, not a new security boundary; Kaspa consensus
  stays the only security boundary.

Approval model: **synchronous**. Running the process with the keyfile
is consent; there is no out-of-band approval channel
(`asynchronousApproval: false`), so consumers requiring async approval
refuse this adapter in negotiation, correctly.

## 3. Network model — the dual unlock

One adapter instance operates on exactly ONE network; default
`testnet-10`. Mirroring the product's mainnet posture
(`POLICYVAULT_ALLOW_MAINNET` + explicit mainnet RPC URL), **mainnet is
refused unless BOTH are present**:

1. `{ allowMainnet: true }` construction/generation option
   (CLI: `--allow-mainnet`), AND
2. environment `PV_CLI_SIGNER_ALLOW_MAINNET=1` (exactly `"1"`).

Every partial combination fails closed with `WRONG_NETWORK`
(`network-unlock.test.js` proves the full matrix, including non-`"1"`
env values and non-boolean options). Additional network fail-closes:

- a keyfile is bound to its network; loading it under a differently
  configured adapter refuses (`WRONG_NETWORK`);
- a request whose `network` differs from the adapter's is refused both
  by `executeSigning`'s live-network gate and by the adapter's own
  defense-in-depth binding check;
- unknown network strings are refused everywhere (closed v1 vocabulary).

Unit tests generate **testnet test keys only**; no mainnet-labeled key
is ever created in tests (the mainnet matrix is proven at the
construction/generation gate, plus a tampered-network-label refusal
fixture over a throwaway testnet key).

## 4. CLI surface (offline)

`node core/signer/adapters/cli/cli.js <command>` — stdout is always one
JSON document; errors are `{"error":{"code","message"}}` on stderr;
exit 0 / 1 (refused) / 2 (usage).

| Command | Does |
|---|---|
| `generate --out FILE [--network N] [--label L] [--allow-mainnet]` | create a NEW keyfile (never overwrites), print PUBLIC identity |
| `identity --key FILE` | validate the keyfile, print PUBLIC identity |
| `sign-message --key FILE --message-file F` | sign the file's EXACT UTF-8 bytes verbatim (personal-message domain), print signature JSON |
| `sign-tx --key FILE --request-file F` | consume a frozen signing-request JSON produced elsewhere, sign exactly the named inputs, print the signed serialization |

The signing commands drive the REAL interface pipeline
(`createMessageSigningRequest` / `createTransactionSigningRequest` +
`executeSigning`) — the CLI is a consumer of the interface, not a
bypass. `sign-tx` consumes the closed
`policyvault-cli-signing-request/1` schema (exact-version match; unknown
versions/kinds/keys refused fail-closed) and returns the signed Safe
JSON with the **transaction id re-derived and required equal to the
unsigned id** (frozen-txid discipline; the downstream SDK finalizer
still independently re-derives it — no txid claim is printed). Message
files are refused if empty or not losslessly-decodable UTF-8 (a lossy
decode would silently sign different bytes).

Offline guarantee: no network transport is loaded anywhere in
adapter.js/cli.js (static scan in `cli.test.js`; the kaspa-wasm load is
isolated behind a lazy injection point — `kaspaModule` handle,
`kaspaModulePath`, `PV_CLI_SIGNER_KASPA_MODULE`, or the same default
path `loadConfig().rustyKaspaModule` uses — precisely so the adapter
never imports `sdk/src/chain.js`, which installs a global WebSocket
transport at require time).

## 5. Interop evidence (UNIT level)

`test/interop-hosted-auth.test.js` proves a CLI-signed identity
authenticates against the EXISTING hosted product's verification code
path — the REAL `server/src/auth.js` `HostedAuthService` with its real
`MemoryAuthStore`, `resolveAddressIdentity`, and kaspa-wasm
`verifyMessage` (the exact call at auth.js:437), unmodified:

1. `createChallenge()` issues the production 7-line challenge for the
   CLI key's address;
2. the CLI adapter signs it through `executeSigning` (and, in a second
   test, the CLI **binary** signs the challenge bytes from a file);
3. `verify()` reconstructs the message server-side, re-derives x-only
   from the submitted 66-hex compressed provider key, binds it to the
   challenge address, verifies the Schnorr signature, and mints a real
   session — `resolveSession()` then returns the CLI wallet as the
   authenticated principal.
4. Negatives hold: tampered signature → `AUTH_SIGNATURE_INVALID`;
   another key's pubkey → `AUTH_ADDRESS_MISMATCH`; nonce single-use
   enforced; personal-message domain separation (an auth signature
   verifies against nothing else).

The ONLY substitution in that flow: `require("websocket")` (RPC
transport pulled in at module load by `sdk/src/chain.js`, unused by
auth) resolves to an offline stub whose constructor throws — doubling
as proof the flow constructs no network transport. Transaction-side
interop: `signTransaction` output re-deserializes via kaspa-wasm with
the named input carrying the 65-byte Schnorr+SIGHASH_ALL signature
script and the txid unchanged (`conformance.test.js`, `cli.test.js`) —
the same shape `sdk/src/signer-dev.js` and KasWare's `signPskt` return.
Full live-node/testnet exercising of a CLI-signed covenant transaction
is future work (see gaps).

## 6. Honest gaps

1. **UNIT-TESTED only.** No live-testnet workflow has been driven with
   this signer; no production flow uses it; the hosted product has not
   been migrated onto `core/signer` at all (spec §14 posture
   unchanged).
2. **No hardware/HSM/MPC/air-gapped adapter yet** — this proves the
   `cli` row of the catalogue; the harder rows (async approval,
   hardware display, QR/file shuttle) remain future work, and the
   asynchronous-approval lifecycle is exercised only by the mock.
3. **Asynchronous approval not exercised here** — this adapter is
   deliberately synchronous; it contributes no evidence about async
   deadline/cancellation behavior beyond declining the capability.
4. **Keyfile at rest is unencrypted** (mode-600 plaintext JSON, like
   default kaspad/bitcoind key material). No passphrase encryption yet;
   an encrypted keyfile format would be an additive
   `policyvault-cli-signer-keyfile/2`. Memory hygiene is best-effort:
   `disconnect()` drops the key handle, but neither JS strings nor
   wasm-held copies can be provably zeroed.
5. **`sign-tx` trusts its request file's transaction bytes** — by
   design the signer signs exactly the frozen bytes it is handed (the
   operator is the signer; verifying that a request matches an approved
   intent is the intent-manifest program's job, not the signer's).
   Operators should obtain request files only from channels they
   trust.
6. **Interop is proven against `MemoryAuthStore`, not PostgreSQL** —
   the crypto/identity path is identical, but no PG round-trip was run
   in these suites (the worktree deliberately touches no PG cluster).
7. **No signature over stderr/argv hygiene beyond scanning** — the
   no-secret scans cover this suite's sessions; they are tests, not a
   syscall-level guarantee.

## 7. File map

| Path | Role |
|---|---|
| `core/signer/adapters/cli/adapter.js` | v1-conformant adapter: keyfile generate/load/validate, dual unlock, signMessage/signTransaction |
| `core/signer/adapters/cli/cli.js` | offline CLI front end (`generate` / `identity` / `sign-message` / `sign-tx`) |
| `core/signer/adapters/cli/testkit.js` | UNIT-test support (kept outside `test/` so the runner never counts it) |
| `core/signer/adapters/cli/test/conformance.test.js` | same-gates-as-the-mock conformance + lifecycle (18) |
| `core/signer/adapters/cli/test/network-unlock.test.js` | mainnet dual-unlock matrix + wrong-network fail-close (11) |
| `core/signer/adapters/cli/test/keyfile.test.js` | keyfile custody hardening / tamper / mode / schema refusals (17) |
| `core/signer/adapters/cli/test/cli.test.js` | CLI end-to-end, request-file refusals, no-secret + offline scans (12) |
| `core/signer/adapters/cli/test/interop-hosted-auth.test.js` | signer-independence interop proof vs real hosted auth (7) |
