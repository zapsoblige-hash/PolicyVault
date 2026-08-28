# PolicyVault Interoperability Adapters (`integrations/`)

**Claim label: IMPLEMENTED + UNIT-TESTED + INTEGRATION-TESTED (against a
real spawned PolicyVault server).** NOT VM-VERIFIED against a covenant on
a live node through these adapters, NOT TESTNET-VERIFIED, NOT
PRODUCTION-HARDENED, NOT EXTERNALLY REVIEWED, NOT AUDITED. No
protocol-ecosystem compatibility is claimed (Kaspa is unregistered
upstream in both x402 and AP2 — see each adapter's README and the
implementation-evidence note).

These are the surface-27 (x402) and surface-28 (AP2) interoperability
adapters, implemented EXACTLY to the committed DESIGNED specs
(`docs/postlaunch/x402-adapter-spec.md`,
`docs/postlaunch/ap2-adapter-spec.md`). Nothing here changes a covenant
byte, a migration, a production file, or the pinned release artifact.

## What these adapters are

Thin, unprivileged, **separately-deployed** translators. Each turns an
untrusted inbound protocol object into an ordinary **closed PolicyVault
transaction intent**, pushes it through the *exact same* authoritative
pipeline every other client uses — via the public Agent API with a
**scoped machine credential** — and, only after real chain proof, renders
the resulting Kaspa txid back as protocol settlement evidence.

An adapter **holds no key, signs nothing, has no privileged path, takes no
custody, converts no currency, and issues no pull credential.** Its
complete absence costs PolicyVault nothing but the translation. This is
structural, not aspirational: the adapters run in their own process and
reach PolicyVault ONLY over HTTP, and a **build-failing dependency-
direction test** (`test/dependency-direction.test.js`) enforces that
`core/**`, `sdk/src/**`, and `server/src/**` never import `integrations/`,
and that the adapter runtime never imports anything but the four
sanctioned SDK leaf modules through `integrations/lib/`.

## Layout

```
integrations/
  lib/            shared, adapter-neutral machinery
    pv-client.js        the ONLY doorway to PolicyVault: the packaged SDK
                        http-client + the six-scope contract + the two
                        network gates (capabilities + live node)
    canonical.js        canonicalJsonStringify REQUIRED FROM THE SDK
                        public entry (never reimplemented) + domain digests
    digests.js          the specs' §3.4 idempotency-key derivations
    amounts-gate.js     canonical-sompi / minor-unit gates (MAX_SOMPI from
                        the SDK; no floats, no conversion)
    address.js          literal-form gates in front of the ONE authoritative
                        rusty-kaspa address parser
    json-guard.js       strict JSON/base64(url): dup-key/proto/depth/lexical
                        -number/NUL/UTF-8 refusals + byte-verbatim capture
    payee-directory.js  operator-configured payee.id -> address (AP2)
    attempt-store.js    create-only, write-once, quarantined attempt records
    settlement.js       settlement claimed ONLY from CHAIN_VERIFIED
  x402/           surface 27 — HTTP-native pay-first client/payer adapter
  ap2/            surface 28 — AP2 Credential-Provider adapter
  test/           UNIT + ADVERSARIAL + INTEGRATION + DEGRADATION suites
```

## Running the tests

```
# from the repo root (real rusty-kaspa wasm required; the SDK's real
# silverc/encoder/tx-probe binaries must exist under
# tests/vm/target/debug for the INTEGRATION suites' real builds)
node --test integrations/test/lib-json-guard.test.js \
             integrations/test/lib-store-settlement-digests.test.js \
             integrations/test/x402-normalize.test.js \
             integrations/test/ap2-sdjwt.test.js \
             integrations/test/ap2-normalize.test.js \
             integrations/test/ap2-constraints.test.js \
             integrations/test/dependency-direction.test.js \
             integrations/test/degradation.test.js

# INTEGRATION (spawns a REAL PolicyVault server; slower — real subprocess
# builds per attempt). Run each on its own for a clean process:
node --test integrations/test/x402-server-integration.test.js
node --test integrations/test/ap2-server-integration.test.js
```

## Zero new runtime dependencies

Node stdlib only (`http`, `crypto`). SD-JWT / JWS parsing and verification
are implemented on `node:crypto` per the AP2 spec. The
dependency-direction test asserts there is no `package.json` anywhere
under `integrations/`.

## Deployment posture (both adapters)

Separate process; loopback HTTP by default; a `pvmk_` machine credential
carrying **exactly** the six scopes `read:network`, `read:vaults`,
`read:requests`, `read:manifests`, `request:build`, `request:submit`, and
never any of `risk:release`, `governance:*`, `request:break-glass`,
`organizations:manage`, `vaults:reconcile`, `request:reject`. The
recommended split gives the external Universal-Signer-Interface signer its
own `request:sign`-only credential, so the adapter never sees a signature.

The credential is supplied to the adapter process out of band (an
environment variable), never a config file, and is never stored in an
attempt record.

See `docs/postlaunch/x402-adapter-implementation-evidence.md` for the
recorded interim decisions on every OPEN QUESTION (CAIP-2 id, KAS asset
literal, currency token, receipt/DAA schemas).
