# PolicyVault Execution Attestations — `policyvault-execution-attestation/1`

**Status: IMPLEMENTED + UNIT-TESTED + ADVERSARIAL-UNIT-TESTED + API-TESTED.**
The optional chain re-check path is additionally **TESTNET-VERIFIED** against a
real testnet-10 node (§11)., NOT a
regulatory artifact of any kind (§2).

| | |
|---|---|
| portable core | `core/attest/` (`canonical.js`, `schema.js`, `record.js`, `verify.js`, `export.js`, `summary.js`, `index.js`) |
| independent verifier CLI | `tools/attestation-verify.js` (zero dependencies) |
| server assembly (v0.4/v0.4.1) | `server/src/attestations.js` |
| server assembly (v0.7 — §12) | `server/src/attestations-v7.js`, dispatched from `server/src/attestations.js` by `schemaVersion` |
| routes | `GET /attestations/requests/:requestId`, `GET /attestations/export` (`server/src/api.js`) |
| scope | `read:attestations` (`server/src/scopes.js`, deny-by-default) |
| SDK client | `getRequestAttestation`, `exportAttestations` (`sdk/src/http-client.js`) |
| tests | `core/attest/test/` (78), `sdk/test/postlaunch-attestations-server.test.js` (14), `sdk/test/postlaunch-attestation-cli.test.js` (11); v0.7 (§12): `sdk/test/postlaunch-attestations-v7.test.js` (9), `sdk/test/postlaunch-attestation-v7-live-chain.test.js` (2) |
| related | `audit-correlation-spec.md`, `intent-manifest-spec.md`, `audit-chain-spec.md`, `dex-adapter-design-spec.md` §5/§9 (the ladder), `hosted-threat-model.md`, `v0.7-app-surface-contract.md` §1 (the `ORG_ROOT_REQUEST` shape §12 maps from) |

---

## 1. What an attestation is

One **PolicyVault policy-execution attestation** is a self-describing,
machine-verifiable evidence record about ONE policy-execution attempt:

- what was requested (vault, action, asset, amount, destination, policy state);
- what PolicyVault **deterministically decided**, and on what evidence
  (the intent-manifest hash and its verdict, the exact digest an external
  signer was shown, the approval quorum);
- what actually happened on Kaspa (the reconciliation ladder and the exact
  outputs a third party can re-read from a node).

It is a **report about evidence that already exists**. It is assembled from
durable records the system already keeps, and its worth is exactly what an
independent reader can re-check without asking PolicyVault anything.

### 1.1 The three claims it makes, and their sources

| claim | source of truth | how a reader re-checks it |
|---|---|---|
| "this is an unmodified record" | the canonical record hash | recompute sha256 over the domain-separated canonical body |
| "PolicyVault decided this, deterministically" | the recorded intent manifest (`policyvault-intent-manifest-record/v1`), re-verified at export time | fetch the manifest by hash and re-run `verifyIntentManifest` |
| "the chain shows this" | a Kaspa node | `attestation-verify --chain`, against any synced node with a UTXO index |

---

## 2. TRUST STATEMENT — what it proves, and what it does not

**It shows:**

1. the exact request, policy state, covenant generation and amounts PolicyVault
   worked from;
2. PolicyVault's deterministic authorization decision, and the machine-readable
   refusal code when it refused;
3. the exact digest an external signer was asked to authorize, and the public
   identity that signed (PolicyVault holds no keys and signs nothing);
4. the approval quorum that was required and collected, by public approver
   identity and per-approval digest;
5. how far the execution actually got on the never-collapsed ladder, and the
   exact chain outputs a reader must query to re-check the top rung.

**It does NOT show, imply, or confer:**

1. **Any opinion of any body outside Kaspa consensus.** It is not a
   certification, not an accreditation, not a licence, not a regulatory
   artifact, and not a security review or audit of any kind; this record
   must never be presented as one.
2. **Any statement about a counterparty**, a venue, a recipient's identity,
   solvency, intentions, or entitlement.
3. **Any authority.** An attestation authorizes nothing, unlocks nothing, and
   is not replayable as a signature, an approval, or a permission.
4. **Any guarantee about the future**, including that a state observed at
   export time still holds.
5. **Correctness of anything the hosted layer merely recorded.** Audit rows
   describe; the covenant decides (`audit-correlation-spec.md` §1). Where the
   record and a Kaspa node disagree, the node wins and the verifier says
   `CHAIN_CONTRADICTED`.

### 2.1 Language rule (binding, test-enforced)

Rendered attestation text may never use the vocabulary of an external approving
body. The forbidden list lives in `core/attest/summary.js`
(`FORBIDDEN_TERMS` / `FORBIDDEN_PHRASES`) and is enforced over the real
renderer output for every vector and every verifier verdict by
`core/attest/test/language.test.js` and again over the live export in the
server suite. Forbidden includes *compliant / compliance / certified /
certification / accredited / regulator / regulatory / audit / audited /
endorsed / notarized / licensed / guaranteed / legal / official* and phrases
such as *"approved by a regulator"*, *"regulatory approval"*, *"legally
binding"*.

The sanctioned vocabulary is exactly:

- **"PolicyVault policy-execution attestation"**
- **"deterministic authorization evidence"**
- **"verified chain outcome"**

### 2.2 MINIMIZED DISCLOSURE, NOT PRIVACY

An attestation carries the **smallest set of facts that makes the outcome
independently checkable**, and nothing else. Every fact it carries is either
already public on chain or is a public identifier the covenant itself binds
(vault id, covenant id, x-only keys, addresses, amounts, txids, state ids).

This is a **disclosure-minimization** property, not an anonymity property. An
attestation is not a privacy tool and must never be described as one: handing
someone an attestation hands them the on-chain footprint of that execution.

The schema has **no slot** for a private key, seed phrase, wallet backup,
bearer token, session token hash, prompt, message content, or personal data,
and the record builder has no path that could add one. Approval evidence is
counts + public approver keys + **sha256 digests** of collected signatures —
never raw signature bytes (§5.4).

---

## 3. Record identity and the canonical hash

```
attestationHash = sha256( "policyvault-execution-attestation-hash/1\n"
                          || canonicalJsonStringify(body) )
```

- `canonicalJsonStringify` is **the project's single canonical serializer**,
  `core/intent/canonical.js`, imported verbatim. `core/attest` deliberately
  does not define a second one (guarded by
  `core/attest/test/purity.test.js`) — a second copy is a silent drift
  surface that only appears as a hash divergence in production (the Phase G-2
  defect class).
- The hash is over **VALUES, not bytes**: object key order is irrelevant, so a
  PostgreSQL `jsonb` round trip re-hashes identically and only a real change
  trips it.
- The **body** is the record minus the two envelope keys `attestationHash` and
  `signature` (a hash cannot cover itself, and the optional signature slot must
  be attachable without re-identifying the record).
- **Every material financial field is inside the hashed body**: amounts, fees,
  destination, asset identity, state ids, policy nonce, covenant generation,
  txid, chain outputs, the ladder, and the authorization decision.

### 3.1 Why this hash carries a timestamp and the manifest hash does not

An **intent manifest** is content-addressed evidence about a transaction:
identical facts must hash identically forever, so its preimage has no
timestamp. An **attestation is a point-in-time observation** — the same
request legitimately yields different attestations as chain depth grows — so
`producedAt` and the observed DAA score are inside the hashed body.

Consequence, asserted in the test suite so it cannot silently change: **two
exports of the same request are two different records with different
identities**, while every underlying fact (txid, manifest hash, ladder) is
identical. A caller that needs a stable reference pins the record it exported,
or pins `outcome.txId` / `authorization.intentManifestHash`, which never move.

---

## 4. The reconciliation ladder (never collapsed)

```
AUTHORIZED -> SIGNED -> BROADCAST -> CHAIN_SEEN -> CHAIN_VERIFIED -> VERIFIED_OUTCOME
```

`outcome.reached` must be a **contiguous prefix** of that list, in order,
without repeats. `outcome.state` is the highest rung reached (or `"REFUSED"`).

| rung | what it means | evidence the verifier requires |
|---|---|---|
| AUTHORIZED | PolicyVault's own durable record: policy, limits and intent were checked before anything was signed | a decision of `AUTHORIZED` |
| SIGNED | an external signer returned a signature; PolicyVault holds bytes, never keys | `authorization.signerXOnly` concrete (the signer-visible digest is corroborating detail — reported as a warning when a source record never captured it, never invented) |
| BROADCAST | a node returned the frozen transaction id — **on its own this is NOT success** | `outcome.txId` |
| CHAIN_SEEN | the expected outputs were observed | at least one observed output |
| CHAIN_VERIFIED | the exact expected effect was proven on chain (script, value, covenant identity) | the exact observed outputs a reader can re-check; below a declared `minDepthDaa` this is `DEPTH_BELOW_MINIMUM`, i.e. CHAIN_SEEN, not CHAIN_VERIFIED |
| VERIFIED_OUTCOME | the **economic result** was proven, not merely the transaction | CHAIN_VERIFIED, plus an explicit outcome source |

`outcome.disposition` runs alongside: `REFUSED`, `IN_PROGRESS`, `SETTLED`
(requires CHAIN_VERIFIED), `FAILED` (incompatible with CHAIN_VERIFIED),
`UNKNOWN`. `FAILED`/`UNKNOWN` must name a `failureCode`.

### 4.1 Refusal attribution (deliberate)

`authorization.decision = REFUSED` means **PolicyVault never produced a
verified authorization**: intent derivation failed, the recorded manifest no
longer verifies, the signer-authority check refused (`AUTHORIZATION_FAILED`),
or the policy quorum was not met (`INSUFFICIENT_APPROVALS`).

Everything else that goes wrong AFTER a valid authorization — a declined
wallet signature, an invalid signature, a stale predecessor, a claim conflict,
a node rejection — exports as `decision: AUTHORIZED` with
`disposition: FAILED` and the exact state as `failureCode`. Reporting a
signer's own refusal as "PolicyVault refused" would misattribute it.

A REFUSED record therefore **may** carry a `VERIFIED_EXACT` intent verdict: the
bytes can match their description exactly while authority is refused. The one
impossibility the verifier pins is a refusal that NAMES a failed intent
verification while also reporting that the verification passed.

A REFUSED record carries **no ladder state and no transaction id** — a txid in
an attestation implies a transaction that exists in the world, and a frozen
but never-broadcast txid is not that.

---

## 5. Schema

Top-level record: the eleven body keys below plus `attestationHash` and
`signature`. Every object has a **closed key set** — an unexpected key is a
failure, not ignored data. Every consensus/accounting value is a canonical
non-negative decimal **string** (no JSON numbers, no floats, no exponents, no
leading zeroes). `NOT_AVAILABLE` is a literal sentinel permitted only where
noted, and never where a reached rung depends on the field.

```
attestationVersion  "policyvault-execution-attestation/1"   (EXACT match; unknown => fail closed)
producedAt          ISO-8601 UTC, millisecond precision
producer            { software, buildId|NA, component, sources[] }   sources = the durable record schemas consulted
subject             { requestId|NA, vaultId, organizationId|null, networkId,
                      contractVersion, policyNonce|NA, stateBefore|null|NA, stateAfter|null|NA }
action              { type, highLevel|null, role|NA, aboveThreshold }
authorization       { decision, refusalCode|null, intentManifestHash|NA,
                      intentManifestVerdict|NA, signerVisibleDigest|NA, signerXOnly|NA }
approvals           { required, collected, approverSlots[], packageCommitment|null,
                      approvalDigests[{ slot, approverXOnly, signatureDigest }] }
asset               { kind: KAS|TOKEN, descriptorHash|null, familyId|null, unit: sompi|atomic }
destination         { kind, identity|null, scriptHex|null }
amounts             { amount|NA, networkFeeSompi|NA, protocolFeeSompi|null }
outcome             { state, disposition, failureCode|null, reached[{state,source,note}],
                      txId|null, networkId,
                      chain: { acceptingBlockDaaScore|null, observedVirtualDaaScore|null,
                               depthDaa|null, minDepthDaa|null,
                               predecessorOutpoint|null, successorOutpoint|null,
                               successorStateId|null, covenantId|null, scriptSha256|null,
                               outputs[{ index, address, valueSompi, covenantId|null, blockDaaScore|null }] } }
attestationHash     64-hex (envelope; excluded from its own preimage)
signature           null | { scheme, keyId, publicKey, value, signedAt }   (envelope; §5.5)
```

### 5.1 Covenant generation (`subject.contractVersion`)

A closed set: `policyvault-0.2 / 0.3 / 0.4 / 0.4.1 / 0.5 / 0.6 / 0.7-root /
0.7-payment` (the last two added by Wave 2 Track G — §12). An unknown or
invented generation **fails closed** (`CONTRACT_VERSION_UNSUPPORTED`) — it is
never routed to a default reader. A known-but-wrong generation is caught by the
caller's expectation pin (§6.2).

### 5.2 `NOT_AVAILABLE` is explicit, never fabricated

A fact no durable record carries is the sentinel string, and the verifier
reports it. Present cases:

| field | when | verifier behaviour |
|---|---|---|
| `authorization.intentManifestHash` | executions that predate intent-manifest recording (`audit-correlation-spec.md` §10 — verification claims are **never** backfilled) | warning `INTENT_MANIFEST_NOT_RECORDED` |
| `authorization.signerVisibleDigest` | an imported transcript that never captured the digest | warning `SIGNER_DIGEST_NOT_RECORDED` |
| `outcome.chain.acceptingBlockDaaScore` | PolicyVault's v0.4 receipts do not persist it today (§10 residual) | warning `ACCEPTING_DAA_NOT_RECORDED`; the record then states no confirmation depth |
| `subject.requestId`, `producer.buildId`, `subject.policyNonce` | records produced outside the hosted request pipeline | shape only |

### 5.3 Observed outputs are only what was PROVEN

`outcome.chain.outputs` lists **outputs whose presence PolicyVault actually
proved**, each with the address a reader must query. From the hosted pipeline
that is exactly the successor outpoint the receipt proves (receipts are written
only after `proveExpectedEffectV4`); the remaining outputs of the same
transaction are described by the referenced intent manifest and are **not**
claimed as observed.

The address is recomputed from the scriptPublicKey the manifest already
committed to, through the sanctioned read-only SDK leaf
`sdk/src/tx-identity.js` — a recomputation from committed evidence, not a new
source of truth. If it cannot be derived the export **fails closed** rather
than silently downgrading the ladder.

### 5.4 Approvals: counts and digests, never signatures

A collected M-of-N approval is a 65-byte Schnorr signature over the frozen
covenant input. Once broadcast it is public on chain inside the signature
script, so omitting it buys no confidentiality — and carrying it buys no
evidence either, because the chain copy is authoritative and this record is not
the place to re-litigate consensus. `sha256(signature)` binds "the approval I
hold is the approval this attestation counted" for anyone who legitimately
holds the package, keeps the record small, and removes any temptation to
mis-read the record as a replayable authority artifact. **Raw signatures are
never carried.**

`approvals.required` is the number of approvals **this execution** required
(`0` when the spend was below the policy threshold), not the vault's standing
M. The verifier enforces `collected >= required` once SIGNED is reached on an
above-threshold execution, that `collected` equals the number of digests, and
that every attributed approver is in the covenant approver set.

### 5.5 The optional detached signature slot

The slot lives **outside** the hashed body, so attaching one never
re-identifies a record already issued.

**No attestation signing key is implemented, deliberately.** Signing would be a
per-deployment operator key over evidence, and this codebase never introduces a
server-held key anywhere near funds. An attestation's authority is its
chain-verifiable facts. Accordingly:

- an unknown `scheme` **fails closed** (`SIGNATURE_SCHEME_UNKNOWN`);
- a well-formed slot in the reserved scheme is reported
  `signature.verified: false`, reason
  `ATTESTATION_KEY_VERIFICATION_NOT_IMPLEMENTED`, plus the warning
  `SIGNATURE_PRESENT_UNVERIFIED`. **A slot must never read as verified.**

A future per-deployment attestation key is recorded as a residual (§10), not
as an implied capability.

---

## 6. Verification procedure

One implementation, `core/attest/verify.js`, shared by the CLI, the server, the
browser and mobile. Three layers, never collapsed:

### 6.1 Layer 1 — structure (offline; no node, no network)

Schema + exact version match + canonical re-hash equality + cross-field
consistency: ladder monotonicity, `refusal => no txid / no ladder / a named
code`, `VERIFIED_OUTCOME => CHAIN_VERIFIED`, disposition agreement, per-rung
evidence, txid binding of the successor and predecessor outpoints, network
binding, integer depth arithmetic, approval quorum and approver-set membership,
and token-family observation.

### 6.2 Layer 2 — expectation binding (optional)

`verifyAttestation(record, { expect: { vaultId, networkId, requestId, txId,
contractVersion } })`. This is how a record that was **re-hashed after
tampering** is caught: a hash proves integrity, not truth. An unknown
expectation key fails closed rather than being ignored — a pin the caller
believed was enforced must never be silently dropped.

### 6.3 Layer 3 — chain facts (opt-in, `--chain`)

`checkChainFacts(record, observation)` is **pure**: the caller supplies the node
observation, so `core/attest` never opens a socket. The CLI supplies it through
`sdk/src/chain.js` (`connectVerified` enforces exact network id + synced +
utxoindex; `getAddressUtxos` reads exactly the addresses
`addressesToQuery(record)` names). Nothing builds, signs, or broadcasts.

| situation | status | verdict |
|---|---|---|
| every declared output matches exactly (value, covenant id, accepting DAA where stated) | `CONFIRMED` | `CHAIN_CONFIRMED` |
| an output is present but disagrees | `CONTRADICTED` | `CHAIN_CONTRADICTED` |
| an output is absent (legitimately spent by a later transition, or never existed) or its address was not readable | `UNCONFIRMED` | `CHAIN_UNCONFIRMED` |
| node unavailable / wrong network / unsynced / no UTXO index | `UNAVAILABLE` | `CHAIN_UNAVAILABLE` |
| the record declares no observations | `NOT_APPLICABLE` | `STRUCTURE_VERIFIED` |

**`CHAIN_CONFIRMED` is the only confirming verdict in the vocabulary, and
`chainConfirmed` is the only boolean that may ever mean "the chain agrees".** A
structurally invalid record is never chain-checked at all.

### 6.4 The CLI

```
node tools/attestation-verify.js <file> [--batch] [--chain] [--rpc <url>] [--network <id>]
        [--expect-vault|-network|-request|-txid|-contract <v>] [--summary] [--json] [--quiet]
```

Exit codes: **0** every record passed the requested level (without `--chain`:
`STRUCTURE_VERIFIED`; with `--chain`: `CHAIN_CONFIRMED`) · **1** at least one
record is invalid or contradicted · **3** `--chain` requested, nothing
contradicted, but something could not be confirmed — *"I could not check"*,
never *"it is fine"* · **2** usage/input error.

The structural pass needs no server, no session, no credential and no network.

---

## 7. Export formats

**Canonical JSON (primary).** `canonicalJsonStringify` over the whole record:
byte-deterministic anywhere in the world, so an export can be diffed, hashed or
pinned in a ticket without a normalization argument.

**Line-delimited batch (NDJSON).** One canonical record per line, newline
terminated. Every line is a complete, independently verifiable record carrying
its own version string, so a batch can be streamed, split, grepped or verified
line-by-line, and a truncated batch degrades into a smaller valid batch. There
is deliberately **no batch header**: it would be a second, weaker place for a
version to live.

**Batch digest.** `computeBatchDigest(records)` commits to the ordered record
hashes under its own domain — reordering or removing a record changes it. It is
**not** a verification: it says nothing about whether any record is valid.

**Read side fails closed.** Every read path (single, batch, digest) checks the
exact version string; a batch reader refuses blank, unparseable, truncated or
non-object lines rather than skipping them — a verifier that silently drops
lines would report "all records valid" over a batch it did not fully read.

---

## 8. Server export

| route | scope | notes |
|---|---|---|
| `GET /attestations/requests/:requestId` | `read:attestations` | one record + the shared verifier's own result over it (warnings included) + a structured summary |
| `GET /attestations/export?vaultId=…\|organizationId=…&limit=&format=` | `read:attestations` | bounded batch (default 50, max 200), `batchDigest`, per-record verification. Exactly one of `vaultId` / `organizationId` is required |

`format=ndjson` returns the line-delimited batch verbatim
(`application/x-ndjson`). Both routes are classified `attestations` in the
operational metrics route enumeration (`server/src/metrics.js`) rather than
falling into `other`, so export traffic is observable on its own line; they
take the ordinary GET `read` rate class and no semaphore
(`server/src/limits.js`) — the work is in-process and bounded by `limit`, and
no node call is ever made.

**Scope.** `read:attestations` is deny-by-default and implied by **neither**
`read:requests` **nor** `read:manifests`: an export bundles a request, its
manifest verdict and its chain proof into one portable document that leaves the
deployment — a deliberate, separately granted capability. It is read-only and
strictly narrower than the tenancy a machine credential already inherits.
Mutation over the namespace is unreachable at any scope.

**Tenancy.** The same covenant-participant scoping as every other read; foreign
or missing objects are 404 (no existence oracle). Organization scoping only
**narrows** to vaults the principal could already read — an org row never
widens participant scoping.

**What the server deliberately will not do** (`server/src/attestations.js`):
it creates **no second source of financial truth** (every field comes from the
wallet request, the G-2-checked intent-manifest record **re-verified now**, the
chain-proof receipt, the vault manifest, or the org assignment); it **never
dials a node** (an export must not fail because the node is down, and a live
read here would be a new claim rather than a report of proven evidence — that
is the reader's job); it **never emits `VERIFIED_OUTCOME`** (no durable
outcome record exists for v0.4/v0.5 spends, and claiming it from a successor
receipt would collapse the ladder); and it **signs nothing**.

---

## 9. Test coverage

`core/attest/test/` — **78 tests**

| file | covers |
|---|---|
| `record.test.js` (12) | hash identity + domain separation, jsonb key-reorder invariance, build determinism, builder self-check, envelope discipline, unknown version fail-closed, signature slot leaves the hash unchanged and never reads as verified, both positive vectors, no-secret sweep, approval digest |
| `tamper.test.js` (32) | byte tamper, field removal, extra field, field substitution, numeric abuse, sentinel abuse, txid substitution, covenant-version substitution, wrong network, wrong vault, wrong asset, ladder regression (gap / reorder / repeat / over-claim / disposition / depth), refusal semantics, quorum forgery — each **naive** (caught by re-hash) and **re-hashed** (caught by consistency, pin, or node) |
| `chain-facts.test.js` (10) | the full disagreement matrix; unavailable / wrong-network / unsynced / no-utxoindex / absent / contradicted can never confirm; invalid records are never chain-checked |
| `export.test.js` (7) | canonical determinism, round trips, NDJSON, empty batch, unknown-version fail-closed on all five paths, no silent line skipping, batch digest commits to content and order |
| `language.test.js` (8) | the forbidden vocabulary, the scanner (hyphenated compounds, mixed case), the rendered summary of every vector under every verdict, the sanctioned vocabulary, no "verified chain outcome" narration below CHAIN_VERIFIED |
| `purity.test.js` (9) | portability gate; exactly one canonicalizer |

`sdk/test/postlaunch-attestations-server.test.js` — **14 tests** (API + SDK +
UNIT): AUTHORIZED-only for a fresh build; the ladder advancing exactly with the
durable evidence; the derived successor address matching the real one;
honest nulls with their warnings; refusal vs post-authorization-failure
attribution over four states; canonical/NDJSON round trips re-verifying
offline; tamper caught by the reader; bounded digest-committed batch export;
400/404 refusals; scope deny-by-default; hosted-mode 401; no-secret sweep;
forbidden-vocabulary sweep; the genesis accounting shape; and
organization-scoped export narrowing to assigned vaults only.

`sdk/test/postlaunch-attestation-cli.test.js` — **11 tests** (INTEGRATION,
the real CLI as a separate process over real files): the exit-code contract a
third party relies on (0 / 1 / 2 / 3), single vs pretty-printed vs NDJSON
input, one bad record failing a whole batch, expectation pins catching a
re-hashed substitution, unknown version failing closed, no silent line
skipping, the `--json` report shape, and the `--summary` render passing the
forbidden-vocabulary scan.

### 9.1 Tamper classes and how each is caught

| class | naive (no re-hash) | re-hashed |
|---|---|---|
| byte tamper | `HASH_MISMATCH` | — |
| field removal / extra field | `HASH_MISMATCH` | `SCHEMA_INVALID` (closed key set) |
| field substitution (amount, fee, manifest, signer) | `HASH_MISMATCH` | `NUMERIC_INVALID` / `NOT_AVAILABLE_NOT_PERMITTED` / `SIGNED_WITHOUT_SIGNER_EVIDENCE` |
| txid substitution | `HASH_MISMATCH` | `TXID_MISMATCH`; if the outpoint is moved too, the expectation pin or the node |
| covenant-version substitution | `HASH_MISMATCH` | `CONTRACT_VERSION_UNSUPPORTED` (unknown) / `EXPECTED_CONTRACT_VERSION_MISMATCH` (known-but-wrong) |
| wrong network | `HASH_MISMATCH` | `NETWORK_MISMATCH`; if both are moved, the pin or `NODE_WRONG_NETWORK` |
| wrong vault | `HASH_MISMATCH` | `EXPECTED_VAULT_MISMATCH` |
| wrong asset | `HASH_MISMATCH` | `ASSET_FAMILY_NOT_OBSERVED` / `ASSET_SHAPE_INVALID` |
| stale outcome / ladder regression | `HASH_MISMATCH` | `LADDER_ORDER_INVALID`, `VERIFIED_OUTCOME_WITHOUT_CHAIN_VERIFIED`, `LADDER_STATE_MISMATCH`, `DISPOSITION_INCONSISTENT`, `DEPTH_BELOW_MINIMUM`, `DEPTH_ARITHMETIC_INVALID` |
| unverifiable chain evidence | — | `CHAIN_UNCONFIRMED` / `CHAIN_UNAVAILABLE` / `CHAIN_CONTRADICTED` — **never** confirmed |

---

## 10. Residuals (honest)

1. **No attestation signing key.** The detached slot is designed; no key, no
   signer, no verifier. A per-deployment attestation key is future work and is
   an owner decision, not an implementation detail (§5.5).
2. **The accepting block's DAA score is not persisted.** `policyvault-receipt/v1`
   does not record it, so server-built attestations state no confirmation
   depth (warning `ACCEPTING_DAA_NOT_RECORDED`) and `DEPTH_BELOW_MINIMUM`
   cannot fire for them. Adding it to the receipt would strengthen every future
   attestation and is an additive change on the reconciliation writer.
3. **`VERIFIED_OUTCOME` has no hosted producer.** The schema, the verifier and
   the v0.6 live-testnet vector exercise it; the hosted pipeline keeps no
   durable outcome record for v0.4/v0.5 spends and therefore never emits it.
   The DEX/swap outcome store (`dex-adapter-design-spec.md` §5) is where a
   hosted producer belongs.
4. **v0.4/v0.4.1 only, server side (`server/src/attestations.js`).** The intent
   bridge supports the v0.4 build routes, so hosted exports through THAT module
   are KAS-denominated. Token (v0.5) and swap (v0.6) generations need their own
   additive mapping when their durable records land; the schema already
   carries `asset`, `protocolFeeSompi` and the token family binding, and the
   v0.6 vector proves the shape. v0.7 (organizational root + rooted vault) now
   HAS its own additive mapping, `server/src/attestations-v7.js` (§12) — but its
   own residuals apply: genesis kinds (`rootGenesis`, `rootedVaultGenesis`) are
   not mapped, only `rootAction`; standalone delegate-spend/deposit requests
   are mapped against a small explicit envelope rather than a real durable
   record shape, because `sdk/src/wallet-requests-v7.js` does not exist yet;
   a rooted-vault owner operation riding in a root action reports zero
   approvals of its own (the root action's own attestation carries the real
   M-of-N evidence, and the schema has no cross-reference field between two
   attestations). Within v0.4, genesis and transition builds carry DIFFERENT
   accounting shapes and are mapped
   explicitly (a genesis has no predecessor state, no payment and no covenant
   sighash — it spends ordinary fuel, so the signing identity comes from the
   committed manifest and the signer-visible digest is honestly
   `NOT_AVAILABLE`). A build shape the mapper does not recognise yields
   `NOT_AVAILABLE` rather than a coerced value: a stringified `undefined` in a
   financial field is exactly the defect class this schema exists to prevent.
5. **Terminal recover exports stop below CHAIN_VERIFIED.** The v4 receipt
   records `successorOutpoint: null` for a terminal recover, so there is no
   proven outpoint to name for re-checking; the record honestly stops rather
   than claiming an unverifiable rung.
6. **No MCP tool yet.** Adding one is trivially consistent with
   `mcp/src/tools.js`, but it changes the published MCP surface and therefore
   belongs with an MCP release under the exact-tarball clean-consumer gate.
   Recorded as follow-up.
7. **Not in `web/core-bundle.js` yet.** `core/attest` is portable by
   construction and purity-gated, but embedding it triggers the bundle regen +
   anti-drift + mobile `sync:portable` chain; recorded as follow-up so the
   browser/mobile verifier lands with that chain's own evidence.
8. **PostgreSQL-backed tests were not run on this lane** (no
   `POLICYVAULT_TEST_PG_*`); the JSON backend was used. The canonical hash is
   values-only and the jsonb key-reorder invariance is asserted directly, but a
   live-PG round trip of an exported record is the residual proof.
9. **Not a security review or audit.** Never claim otherwise.

---

## 11. Live evidence (chain re-check path)

Run against the local testnet-10 node (kaspad v2.0.1, synced, utxoindex) over
the attestation built read-only from `docs/testnet-v6-atomic-evidence.json`
(the v0.6 atomic SELL, `edc0d8eb7d485f0d537298d0dd071d4d7771c0ef48fa9ddb72e11a81538c7705`):

```
node.available true   node.network true testnet-10   node.usable true
output[0..3]   false  not present in the current UTXO set (spent by later transitions) — cannot confirm
output[4]      true   exact match at kaspatest:qqt3gtmf2d0ymtgdcurqmaj9c4dpwnxph7jmn6ewtx4d9t5kquklcdsy84dwm
STATUS UNCONFIRMED    verdict CHAIN_UNCONFIRMED     exit 3
```

The venue protocol-fee output (19,550,170 sompi) matched **exactly** on value,
covenant and accepting DAA score; the four covenant outputs had been spent by
later transitions and were reported UNCONFIRMED — never confirmed, never
falsified. This is the intended behaviour and the reason the vocabulary
separates "I could not check" from "it is fine".

---

## 12. v0.7 ORGANIZATIONAL ROOT mapping (Wave 2, Track G)

Status: **IMPLEMENTED + UNIT-TESTED + ADVERSARIAL-UNIT-TESTED**, the chain
re-check path **TESTNET-VERIFIED** against a real, currently-live testnet-10
node (§12.4). NOT API-TESTED (no HTTP route exercises this mapping yet — see
§12.5).

`server/src/attestations-v7.js` maps the v0.7 `ORG_ROOT_REQUEST` durable
record (`docs/postlaunch/v0.7-app-surface-contract.md` §1) into
`policyvault-execution-attestation/1` records under two contract versions,
because a single v0.7 root transaction can carry a root governance change AND
zero or more rooted-vault owner operations at once, and each gets its OWN
attestation:

- **`policyvault-0.7-root`** — the organizational root's own governance
  action: `authorize`, `rotate`, `freeze`, `unfreeze`, `ownerRecover`,
  `succession` (`buildAttestationForOrgRootRequest`). `action.type` is the
  action name; `action.highLevel` carries the action's authority CLASS
  (`AUTHORITY-REDUCING` / `-NEUTRAL` / `-EXPANDING` / `TERMINAL`, from
  `core/model/owner-set-v7`'s own table, restated from the RE-VERIFIED
  manifest — never from the unverified request row); `action.aboveThreshold`
  is always `true` (an owner-root action always requires reaching a declared
  M-of-N/K-of-N/R-of-N quorum, or the pinned successor key for succession).
  The recorded `policyvault-org-root-manifest/1` is **RE-VERIFIED NOW**
  through `verifyOrgRootIntentManifest` — never trusted by marker, the exact
  G-2 discipline `server/src/attestations.js` already applies to v0.4
  manifests.
- **`policyvault-0.7-payment`** — a ROOTED-VAULT operation, either (a) an
  owner operation riding INSIDE the same root transaction
  (`buildAttestationsForOrgRootRequestVaultOps`, one attestation per entry of
  `manifest.vaultOperations[]`, sharing the root action's own observed chain
  state) or (b) a standalone delegate spend / deposit with no root input at
  all (`buildAttestationForRootedVaultRequest`). Both funnel through the same
  `mapRootedVaultAttestationBody`, fed from a real
  `policyvault-rooted-vault-manifest/1`. A `tokenAgentSpend` attests
  `asset.kind: "TOKEN"` with the recipient's x-only key as
  `destination.identity`; every other rooted-vault owner action attests
  `asset.kind: "KAS"`.

### 12.1 Approvals: what is, and is not, reconstructed

For a `policyvault-0.7-root` attestation, `approvals.approvalDigests` is built
from the request's per-slot `responseEnvelopeHash` values — **not**
`sha256(signatureHex)` as §5.4 defines it in the general case. The durable
`ORG_ROOT_REQUEST` record (per the app-surface contract) stores a hash of the
whole BOUND response envelope per slot, not a digest of the bare 65-byte
signature alone; until a raw-signature digest is separately persisted, the
envelope hash is used as a genuine, still-real per-approval binding — just
over a slightly wider domain than the general-case definition. Stated here,
not silently substituted.

A `policyvault-0.7-payment` attestation for a rooted-vault owner op riding in
a root action reports `approvals.required: "0"` / `collected: "0"`: its
authority is entirely inherited from the ROOT action's own M-of-N approvals in
the SAME transaction, attested separately, and the schema has no field to
cross-reference one attestation to another — a reader who needs the quorum
evidence fetches the root action's own attestation for the same underlying
transaction id. A standalone delegate spend is POLICY-gated (agent Merkle
proof, per-transaction cap, period budget), never an M-of-N approval quorum of
its own, so `required: "0"` is the honest mapping there too (mirrors v4's
below-threshold convention).

### 12.2 `signerXOnly`: one real co-signing owner, not "the" signer

A v0.7 root action has M co-signers, not one. Once the ladder reaches SIGNED,
the schema still requires a single concrete `authorization.signerXOnly` — so
`buildAttestationForOrgRootRequest` reports the FIRST slot whose status is
`SIGNED` (a real, verified owner public key, never a synthesized one), and the
same convention is used for an embedded vault op's attestation. The FULL
multi-party evidence — every collected slot and its digest — lives in
`approvals.approvalDigests`, which a reader should treat as the authoritative
M-of-N record; `signerXOnly` is one member of it, restated for schema
compatibility with the singular-signer generations.

### 12.3 What this mapping deliberately will not do

Identical to `server/src/attestations.js`'s own discipline (§8): it never
dials a Kaspa node; it never emits `VERIFIED_OUTCOME` (a request stamped
`VERIFIED_OUTCOME` still attests only through `CHAIN_VERIFIED`); it signs
nothing. Genesis kinds (`rootGenesis`, `rootedVaultGenesis`) are **not
mapped** — a genesis has no predecessor root state and no owner-slot quorum to
attest to, the same reason v0.4 genesis and transition builds get different
accounting shapes rather than one being forced into the other's shape; adding
genesis mapping is a follow-up, not attempted here.

### 12.4 Live evidence (chain re-check path)

Run against the local testnet-10 node (kaspad v2.0.1, synced, utxoindex) over
`core/attest/testutil/vectors-v7.js`'s positive vector, built read-only from
`docs/testnet-v7-org-root-evidence.json` (the real 118-step v0.7 lifecycle
run) — the organizational ROOT's own continuation from the run's LAST step
("19-vault-owner-recover-terminal", a terminal rooted-vault recovery whose
embedded root path is an ordinary `authorize` continuation,
txid `6626f2daedc2d5349d5f099706e9c65dea969af446c04584997ab9bf00d1ef57`):

```
node.available true   node.network true testnet-10   node.usable true
output[1]      true   exact match at kaspatest:pqv688rg97jrpe3qwxq20nunx5cnek3u62rafwac5m0t26tej3q5qhq3dktdp
STATUS CONFIRMED       verdict CHAIN_CONFIRMED        chainConfirmed true
```

The root successor output (200,000,000 sompi, covenant id
`9a654cb0cbf6e67178e0d228bf5fa39ae6aca7655718dcf63166273df135edf6`) matched
**exactly** on value, covenant identity, and address, at the recorded
accepting DAA score — genuinely still live on the real node at the time this
was run (`sdk/test/postlaunch-attestation-v7-live-chain.test.js`). Because a
later, unrecorded transition could legitimately spend that same outpoint
before this test next runs, the suite itself accepts `CHAIN_CONFIRMED` OR the
equally honest `CHAIN_UNCONFIRMED` as passing outcomes and fails ONLY on
`CHAIN_CONTRADICTED` (an output present but disagreeing) — exactly the
vocabulary discipline §11 establishes.

### 12.5 Residuals (honest)

1. **No HTTP route exercises this mapping yet.** `server/src/attestations.js`
   dispatches to it by `schemaVersion`, so `GET /attestations/requests/:id`
   and `/attestations/export` are READY the moment a caller loads an
   `ORG_ROOT_REQUEST` by id and hands it in — but `server/src/org-roots.js`
   (the store/route layer that will do that) does not exist yet on this
   track. `sdk/src/store.js` also has no `Categories.ORG_ROOT_REQUEST`
   constant yet; `attestationsV7.loadOrgRootRequestForAttestation` attempts
   the lookup by the STRING category `"org-root-request"` and fails closed
   with `ATTESTATION_ORG_ROOT_STORE_PENDING` until that lands.
2. **`sdk/src/wallet-requests-v7.js` does not exist yet.** The standalone
   delegate-spend/deposit mapping (`buildAttestationForRootedVaultRequest`)
   is therefore built against a small, explicit envelope of request-level
   facts rather than a real durable record shape — see §12's own module
   header for the exact envelope fields required.
3. **Genesis kinds are not mapped** (§12.3).
4. **`subject.organizationId`** is always `null` from this mapping today: no
   hosted-organization ASSIGNMENT lookup is wired for v0.7 records (the
   on-chain `boundOrgId` a root's own state carries is a DIFFERENT identity —
   see `docs/postlaunch/v0.7-app-surface-contract.md` §0 — and is already
   correctly carried as `subject.vaultId`, never confused with
   `organizationId`).
5. **No MCP tool, no PostgreSQL-backed test run.** Same residuals as §10
   items 6 and 8, inherited unchanged for the v0.7 mapping.
6. **Not a security review or audit.** Never claim otherwise.
