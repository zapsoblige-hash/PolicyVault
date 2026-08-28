# Python reference SDK/client — scope, asymmetry, schema policy, evidence

Status: **DESIGNED + IMPLEMENTED + UNIT-TESTED + INTEGRATION-PROVEN** (real
`server/src/server.js` over real HTTP, spawned from this tree). NOT
TESTNET-VERIFIED, NOT PRODUCTION-HARDENED, NOT EXTERNALLY REVIEWED.

Covers `FULLSCALE_COMPLETION_ADDENDUM.md` surface **10 — Python reference
SDK/client**, as a client under the "CLIENTS" module boundary.

Package: `python/policyvault_client/` (`policyvault-client`, Apache-2.0,
Python ≥ 3.10, **zero third-party runtime dependencies**). Not published —
publication of any PolicyVault artifact is an explicit owner gate.

---

## 1. Anti-bloat compliance

The addendum's architectural rule is that there remains ONE authoritative
deterministic financial/policy core, and that every client is a thin
consumer around it. This package implements **nothing** on that list:

| Forbidden for a client | Present in Python? |
|---|---|
| financial authority | no |
| transaction-policy semantics | no |
| successor-state derivation | no |
| governance authority / classification | no |
| risk decision composition or bypass | no |
| transaction verification | no |
| signer authorisation | no |
| reconciliation truth | no |
| fee / mass computation | no |
| key custody or signing | no |

What it does implement, and nothing beyond it:

1. **Transport** — `urllib.request` + `json`, one API root, one optional
   bearer credential (`transport.py`).
2. **Closed request schemas** — dataclasses that refuse unknown fields
   locally (`schemas.py`).
3. **Integer/amount hygiene** — a port of the RULES in
   `core/model/amounts.js` (`amounts.py`).
4. **Typed exceptions** carrying the server envelope verbatim
   (`errors.py`).
5. **Method surface** over the documented routes (`client.py`).

Every consequential decision is a server round trip into the existing
pipeline (`classifyActionV4`, `evaluateRisk`, `planV4`,
`assertSignerAuthorizedV4`, `buildV4Transaction`, `deriveAndVerify`).

## 2. The JS/Python asymmetry — stated honestly

`COMPLETION_STANDARD.md` requires that a client can **independently detect
server/frontend manipulation before signing**. The JavaScript SDK satisfies
that by shipping the portable deterministic core: the browser re-derives the
intent manifest and recomputes Merkle roots itself
(`web/verify-intent.js`, `docs/postlaunch/intent-manifest-spec.md`,
`docs/postlaunch/f1-merkle-portability.md`).

**Python has no port of that core, and this client therefore cannot perform
independent local verification.** This is a real, named limitation, not an
oversight:

* Everything a build/simulate call returns is the *server's* claim about what
  it did. Python can check that the answer is well-formed and integer-clean;
  it cannot check that the successor script, fee, mass, or manifest hash are
  the ones the covenant will actually enforce.
* The covenant remains the security boundary either way: a hostile server
  cannot make Kaspa consensus accept a policy-invalid transaction, and the
  signer still holds custody. What a Python-only pipeline lacks is a **second
  opinion between "the server said so" and "I signed it."**
* A Python caller who needs that second opinion must run the **JS core**
  (Node) over the manifest/build output before signing. The recommended
  shape is: Python orchestrates and requests; the JS core verifies; a
  Universal Signer Interface adapter signs.

**Why a Python port is refused, not merely deferred.** A second
implementation of consensus-visible logic is precisely the
cross-runtime-disagreement hazard the architecture is built to avoid
(`docs/postlaunch/cross-runtime-equivalence.md`). Two implementations that
disagree by one sompi on a fee, or by one byte on a successor script, produce
a transaction one runtime calls valid and the other calls invalid — resolved
only by chain consensus, after funds have moved. The
`boundVaultId` incident (`docs/v02-production-boundary-audit.md`) is the
project's own precedent for how such a defect passes every in-process test and
fails every real transaction. ONE core, many thin clients.

An honest caveat on the reverse direction as well: even the JS core is one
implementation, and its agreement with the covenant is established by the VM
and production-byte suites — not by this client.

## 3. Schema policy

### 3.1 Closed on input

Every mutating body is built from a dataclass in `schemas.py`. There is no
code path that forwards an arbitrary mapping. `from_mapping` accepts either
the Python field name or its `camelCase` wire name and **refuses anything
else**, because an unrecognised field is either a client bug or a version
mismatch and forwarding it would hide both.

An unknown v0.4 action fails closed **locally**, before a request exists —
the server would refuse it too, but a local refusal costs no round trip and
discloses no intent.

### 3.2 What is validated, and what deliberately is not

Validated (transport-level, matching the server's own lexical input checks):

* field names and presence/absence,
* carrier types and integer hygiene,
* lexical shape: 64-char lowercase hex for vault ids / x-only keys /
  manifest hashes, even-length hex for scripts and signatures, bounded
  opaque ids for path segments, bounded integer knobs.

**Not** validated, on purpose — each would be a second implementation of
something the authoritative side owns:

* whether an address belongs to the server's configured network. The
  required prefix is derived server-side from `config.networkId`
  (`sdk/src/address-identity.js`); a client that decided it locally would be
  a second network gate and would disagree with a differently configured
  deployment. Shape only: non-empty, no whitespace, prefixed.
* whether an amount is within policy, budget, threshold, or reserve.
* whether an action is governed, risk-relevant, or authorised for a signer.
* anything about successor state, fees, mass, or covenant bytes.

### 3.3 Versioned platform schemas

Every v0.4 wallet-request body this client sends carries
`schemaVersion: "policyvault-wallet-v4-request/v1"`
(`server/src/api-version.js`). The server fails closed with
`422 SCHEMA_VERSION_UNSUPPORTED` on a version it does not know, and never
routes an unknown version to a default handler — so a pinned client is
guaranteed either that exact behaviour or a clean refusal, never silent
drift.

`assert_compatible()` performs the handshake explicitly against
`GET /capabilities` and raises rather than proceeding on a mismatch.

Governance bodies are **not** stamped: they are not part of the v4
wallet-request schema family, and stamping them would assert a version the
route never validates.

### 3.4 Amount rules ported from `core/model/amounts.js`

`SOMPI_PER_KAS`, `MAX_SOMPI`, `parse_sompi`, `parse_positive_sompi`,
`kas_to_sompi`, `sompi_to_kas` mirror the canonical parser's rules. The
VECTORS from `sdk/test/amounts.test.js` are re-tested here (the vectors, not
the code — agreement is evidence, not tautology).

Three Python-specific hardenings, all failing **closed** (never more
permissive than the server):

| hazard | rule |
|---|---|
| Python `\d` matches Unicode digits (U+0663 …); JS `\d` matches `[0-9]` only | every pattern spells `[0-9]` explicitly |
| Python `str.strip()` strips more than JS `trim()` (U+00A0, U+FEFF, …) | trims only `" \t\n\r\v\f"` |
| Python `bool` is a subclass of `int`, so `True` would parse as 1 sompi | `bool` rejected wherever an integer is expected |

Additionally: `Decimal`/`Fraction` are rejected as non-canonical carriers;
amounts always leave as decimal **strings** (JSON numbers are doubles, sompi
exceeds 2\*\*53); and a float **anywhere** in a request body is refused before
encoding, since no PolicyVault body legitimately contains one.

## 4. Credential handling

* A token is wrapped in `transport.Secret` on acceptance. `__repr__`,
  `__str__`, and `__format__` render `<policyvault Secret: redacted>`;
  `reveal()` is called exactly once per request, assembling the
  `Authorization` header.
* The package **never** imports `logging` and never writes to stdout/stderr,
  so there is no sink to leak into. Proven mechanically, not by convention.
* Redirects are refused (`_NoRedirects`) so `urllib` can never re-send the
  `Authorization` header to a host named by a 3xx.
* Environment proxies are disabled by default (`ProxyHandler({})`) so a
  proxy never observes the credential; opt in with `trust_env_proxy=True`.
* No client method exists for `/identities*`. Machine-identity management is
  wallet-session-only (`server/src/scopes.js isWalletSessionOnlyRoute`): a
  token can never mint, widen, or revoke its own or a sibling's authority.
  The integration suite proves the server refuses it via the raw transport.

## 5. Idempotency, retries, and the dry run

* `Idempotency-Key` is caller-supplied per call, or generated by
  `new_idempotency_key()` (256-bit `secrets`). One key per **logical
  operation**, reused across retries — that is what makes a retry safe.
* `auto_idempotency` is **off by default**. Two reasons, both deliberate:
  a fresh random key per attempt provides no replay protection; and an
  idempotency-keyed POST makes the server persist a claim record, which
  would give the deliberately zero-persistence `simulate` route a durable
  side effect. `simulate` is never auto-keyed even when the option is on.
* **No retries at any layer.** A `TransportError` on a mutating POST is
  genuinely ambiguous about whether the server executed it; retrying is the
  caller's explicit decision and is safe only with the original key.
* `simulate()` surfaces `ok:false` + `refusalReason` as **data**, never as an
  exception — a dry run answers "would this succeed", and only malformed
  input is a real 4xx. `vmPreflight.skipped` is passed through unchanged
  rather than smoothed over.

## 6. Method surface

| area | methods |
|---|---|
| health / discovery | `health`, `readiness`, `capabilities`, `assert_compatible` |
| network | `network_status`, `fuel` |
| vaults | `list_vaults`, `get_vault`, `vault_status`, `vault_audit`, `reconcile_vault` |
| audit / manifests | `audit`, `get_manifest` |
| v0.4 requests | `simulate`, `build_request`, `create_vault`, `list_requests`, `get_request`, `approve_request`, `finalize_request`, `submit_request`, `genesis_submit`, `reject_request` |
| governance | `list_proposals`, `get_proposal`, `create_proposal`, `approve_proposal`, `cancel_proposal` |
| risk | `get_risk_evaluation`, `release_risk_evaluation` |

`readiness()` returns its body for both 200 and 503, because a 503 there is a
well-formed `{ready:false, reason}` answer rather than an error envelope.

`create_vault()` is the one method that forwards a caller-supplied mapping.
The create route accepts two different documented body schemas, and the
browser-oriented "friendly" one is normalised server-side against live DAA
score; modelling it as a closed schema would mean encoding KAS→sompi, period,
and approver normalisation rules the server owns. It is documented as such
rather than half-modelled.

## 7. Test evidence

Run from `python/`:

```bash
python3 -m unittest discover -s tests -t .
```

**75 tests, all passing** (Python 3.14.4, Node v20.20.2):

| module | layer | tests | proves |
|---|---|---|---|
| `test_amounts.py` | UNIT | 19 | parser-rule parity with the vectors from `sdk/test/amounts.test.js`; float/`bool`/`Decimal`/`Fraction`/Unicode-digit refusal; amounts leave as strings; a float anywhere in a body is refused |
| `test_schemas.py` | UNIT | 16 | unknown fields refused locally; snake/camel equivalence; duplicate-field refusal; unknown action fails closed; lexical shape; address shape is not a network decision; `schemaVersion` stamping |
| `test_secret_redaction.py` | UNIT | 12 | the token never appears in repr/str/format/exception/traceback/pickle/`vars()`; no logging sink; nothing written to stdout/stderr; **all imports are stdlib** (AST-checked) |
| `test_live_server.py` | INTEGRATION | 28 | see below |

The integration suite uses **no mock server**. `python/tests/_server_boot.js`
starts `server/src/server.js` `createServer(config)` from this tree on an
ephemeral loopback port (JSON backend, throwaway data root, `authMode:
enabled`), seeds one v0.4 vault manifest, and mints two machine credentials —
full-scope and read-only — through a real hosted wallet session with a real
Schnorr signature. Python then speaks real HTTP to the real handler.

Properties proven against the live server:

* health / readiness / capability discovery are public and match code truth;
  the schema handshake passes here and fails closed on a mismatch;
* the **true dry run** answers `ok:true` off the real builder (real fee,
  successor, intent verdict), turns substantive refusals into `ok:false` +
  `refusalReason`, and persists nothing observable;
* **idempotency**: the same key replays the original response verbatim
  (`replayed:true`, identical `requestId`/`txId`, exactly one durable
  request); a different body under the same key is a deterministic
  `409 IDEMPOTENCY_KEY_CONFLICT`; malformed keys are refused locally;
* **deny-by-default scopes**: a read-only credential reads vaults but is
  refused `simulate` (`request:build`), `audit` (`read:audit`), and
  `risk:release`, each with `403 SCOPE_FORBIDDEN` naming the missing scope;
* `/identities*` is refused with `MACHINE_IDENTITY_ROUTE_FORBIDDEN` for a
  machine credential regardless of scope;
* an invalid credential fails at authentication (`401
  MACHINE_TOKEN_INVALID`), and an **unauthenticated** programmatic mutation
  is refused at the origin wall (`403 ORIGIN_REQUIRED`) — the cookie-free
  bearer exemption is not a blanket bypass;
* the error envelope reaches the caller **verbatim**, route-specific extras
  included; `422 SCHEMA_VERSION_UNSUPPORTED` maps to `SchemaVersionError`;
  a foreign proposal is hidden as 404 rather than denied.

### 7.1 Environment dependency (classified: ENVIRONMENT)

The v0.4 builder shells out to the real Rust probes under the gitignored
`tests/vm/target/debug/` (`pv_call_encoder`, `pv_tx_probe`). When they are
absent the build-dependent tests **skip** with an explicit remedy rather than
failing — an absent Cargo artifact is an environment gap, and substituting a
stub would defeat the point of testing against the real pipeline.

```bash
cd tests/vm && cargo build --bin pv_call_encoder --bin pv_tx_probe
```

In a git **worktree**, Cargo cannot resolve the sibling
`../../../silverscript` path the manifest declares, so an existing build must
be linked into `tests/vm/target/debug/` instead.

Both paths were exercised. With the probes present: **75 run, 75 pass, 0
skipped**. With `pv_call_encoder` removed: **75 run, 70 pass, 5 skipped** —
the five builder-dependent cases skip with the remedy above and nothing
reports a false failure.

## 8. Known limitations / notes for later surfaces

1. **No local verification** (§2) — the headline asymmetry. Any conformance
   suite (surface 24) exercising the Python path must assert this rather than
   assume parity with the JS SDK.
2. **No signing.** Python never holds a key. A Python-driven flow needs a
   Universal Signer Interface adapter out of process (KasWare, or the
   reference CLI signer, `docs/postlaunch/signer-cli-reference.md`).
3. **`create_vault` forwards a mapping** (§6) — the one un-closed body,
   documented rather than half-modelled.
4. **Unauthenticated mutations are origin-walled, not 401.** Correct
   server behaviour, but surprising the first time; a machine client must
   always present a credential.
5. **No async / connection pooling.** `urllib` opens a connection per
   request (`Connection: close`). Adequate for agent workloads; a high-rate
   client should be measured before assuming it is not the bottleneck. Adding
   `httpx`/`aiohttp` would break the zero-dependency rule and is not
   proposed.
6. **Not exercised against PostgreSQL.** The integration suite runs the JSON
   backend. Backend parity is proven server-side
   (`sdk/test/postlaunch-platform-store-pg.test.js`) and is not a client
   concern, but it means this suite adds no PG evidence.
7. **No hostile-AI-agent / prompt-injection review** (surface 26). Worth
   noting for whoever owns it: this client accepts only closed-schema
   Python objects and never free-form model output, so the injection surface
   here is "an agent misreads an ALLOW/REVIEW/DENY decision", not "untrusted
   text crosses into trusted bytes". That judgement deserves its own
   adversarial pass, not a self-assessment here.

## 9. Files

| path | role |
|---|---|
| `python/policyvault_client/__init__.py` | public surface |
| `python/policyvault_client/amounts.py` | integer/decimal-string hygiene (RULES ported from `core/model/amounts.js`) |
| `python/policyvault_client/errors.py` | typed exceptions carrying the envelope verbatim |
| `python/policyvault_client/schemas.py` | closed request schemas |
| `python/policyvault_client/transport.py` | stdlib HTTP, `Secret`, redirect/proxy refusal, float-free JSON encoding |
| `python/policyvault_client/client.py` | the method surface |
| `python/tests/_server_boot.js` | spawns the REAL server + mints test credentials |
| `python/tests/harness.py` | subprocess lifecycle + handshake |
| `python/tests/test_amounts.py` | UNIT |
| `python/tests/test_schemas.py` | UNIT |
| `python/tests/test_secret_redaction.py` | UNIT |
| `python/tests/test_live_server.py` | INTEGRATION |
| `python/pyproject.toml` | `policyvault-client`, Apache-2.0, no dependencies, NOT published |
| `python/README.md` | user-facing documentation |
