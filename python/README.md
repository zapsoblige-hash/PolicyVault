# PolicyVault Python reference client

A **thin, stdlib-only** Python client of the PolicyVault REST/Agent API
(full-scale completion surface 10). Python ≥ 3.10. Zero third-party runtime
dependencies, permanently.

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES FINANCIAL AUTHORITY. SIGNERS RETAIN CUSTODY.**

---

## The one thing to understand before using this

PolicyVault has **ONE authoritative deterministic financial/policy core**, and
it is **not in this package**. The core (`core/`, JavaScript) is what evaluates
policy, classifies governance, composes risk decisions, derives successor
state, computes fees and mass, and verifies transaction-intent manifests. The
Kaspa covenant, verified by consensus, is the actual security boundary.

This client is **transport + closed schemas + integer hygiene**. That is its
entire local role. It contains:

* no policy evaluation,
* no successor-state derivation,
* no fee or mass computation,
* no covenant or intent-manifest verification,
* no signer authorisation,
* no keys, and no signing of any kind.

### The JS/Python asymmetry — stated plainly

The JavaScript SDK ships the portable deterministic core, so a JS/browser
client can **independently re-derive and verify** what the server told it
before a human signs — that is the whole point of
`docs/postlaunch/intent-manifest-spec.md` and `web/verify-intent.js`.

**Python has no port of that core, so this client cannot do that.** A Python
caller who needs independent local verification of a transaction before
signing must run the JS core (Node) on the manifest/build output. Everything
this client returns from a build/simulate call is the *server's* claim about
what it did. The covenant still enforces the rules on chain regardless — a
hostile server cannot make consensus accept a policy-invalid transaction — but
a Python-only pipeline has **no second opinion between "the server said so" and
"I signed it."**

Porting the core to Python is deliberately **not** on the table: a second
implementation of consensus-visible logic is exactly the
"cross-runtime disagreement" hazard the architecture forbids. Two
implementations that disagree by one satoshi on a fee, or by one byte on a
successor script, produce a transaction that one runtime calls valid and the
other calls invalid — and only chain consensus breaks the tie, after funds
have moved. One core, many thin clients.

---

## Install

Not published to PyPI (publication is an explicit owner gate). Install from a
local checkout, or just put `python/` on `PYTHONPATH`:

```bash
pip install ./python          # from the repository root
# or
export PYTHONPATH="$PWD/python:$PYTHONPATH"
```

## Quick start

```python
from policyvault_client import PolicyVaultClient, SimulateV4Spec, AgentSpendParams

pv = PolicyVaultClient()      # $POLICYVAULT_API_URL / $POLICYVAULT_API_TOKEN
pv.assert_compatible()        # fail closed if the server speaks another schema

body = pv.simulate(SimulateV4Spec(
    vault_id="5a" * 32,
    action="agentSpend",
    signer_address="kaspatest:qzwp…",
    params=AgentSpendParams(
        agent_pk="9c1f…",           # 32-byte lowercase hex
        pay_amount_sompi="200000000",  # integer sompi as a string. Never a float.
        recipient="1428…",
    ),
))

simulation = body["simulation"]
if simulation["ok"]:
    print(simulation["review"]["feeKas"], simulation["wouldRequire"])
else:
    print("would be refused:", simulation["refusalReason"])
```

### Credentials

```python
pv = PolicyVaultClient("https://app.policy-vault.org", token="pvmk_…")
```

Machine credentials are minted by a human through an authenticated **wallet
session**, never by a token. `/identities*` is structurally unreachable by any
machine credential regardless of scope, so this client deliberately exposes no
method for it: a token can never mint, widen, or revoke its own — or a
sibling's — authority.

The token is wrapped in a `Secret` the moment it is accepted. It never appears
in a `repr`, `str`, format string, exception, or traceback, and this package
never writes to `logging`, stdout, or stderr at all.

---

## Amount safety

Every consensus/accounting value is **integer sompi**. `policyvault_client.amounts`
is a faithful port of the RULES in `core/model/amounts.js` (never of its code)
and refuses floats at the boundary:

```python
from policyvault_client import kas_to_sompi, sompi_to_kas, parse_sompi

kas_to_sompi("1.23456789")   # 123456789
sompi_to_kas(150_000_000)    # "1.5"
parse_sompi(1.5)             # AmountError — floats are never funds carriers
```

* `int` (arbitrary precision, the analogue of JS `BigInt`) or an exact decimal
  string. Never `float`, `Decimal`, `Fraction`, or `bool`.
* Amounts always leave as **strings**: JSON numbers are IEEE-754 doubles in
  most parsers and sompi routinely exceeds 2\*\*53.
* A float **anywhere** inside a request body is refused before encoding, not
  just in fields named like amounts.
* ASCII-only digits and ASCII-only whitespace trimming — Python's `\d` matches
  Unicode digits and `str.strip()` strips more than JS `trim()` does, so both
  are pinned down explicitly. Both divergences fail **closed**: this client is
  never more permissive than the server.

---

## Closed request schemas

No method forwards an arbitrary `dict`. Bodies are built from dataclasses that
refuse unknown fields locally:

```python
from policyvault_client import WalletRequestV4Spec, ValidationError

WalletRequestV4Spec.from_mapping({
    "vaultId": "5a" * 32, "action": "ownerTopUp",
    "signerAddress": "kaspatest:…", "params": {"topUpAmountSompi": "5"},
    "sneakyExtra": 1,          # -> ValidationError, nothing is sent
})
```

Both `snake_case` and the wire's `camelCase` are accepted; anything else is a
hard local refusal. Unknown v0.4 actions fail closed before a request is made.

What this validation covers, and what it deliberately does not, is spelled out
in `docs/postlaunch/python-client-spec.md` §3. Short version: field names,
carrier types, and lexical shape — never whether an address matches the
server's network, never whether an amount is within policy.

---

## Idempotency

```python
key = pv.new_idempotency_key()          # generate ONCE per logical operation
try:
    result = pv.build_request(spec, idempotency_key=key)
except TransportError:
    result = pv.build_request(spec, idempotency_key=key)   # SAME key: safe
```

Reusing one key across retries is what makes a retry safe — two concurrent
identical calls sharing a key produce exactly one durable request, and a
completed call replays its original response verbatim with
`idempotency: {"replayed": true, …}`. Reusing a key for a *different* body is a
deterministic `409 IDEMPOTENCY_KEY_CONFLICT` and the handler is never called.

`auto_idempotency=True` stamps a random key on mutating POSTs that were given
none. It is **off by default**: a fresh key per attempt buys no retry safety,
and an idempotency-keyed POST makes the server persist a claim record — which
would quietly give the zero-persistence `simulate` route a durable side effect.
`simulate` is never auto-keyed even when the option is on.

**There are no retries at any layer of this client.** A `TransportError` on a
mutating POST is genuinely ambiguous about whether the server executed it.
Retrying is your explicit decision, and safe only with the original key.

---

## Errors

Every server refusal arrives as a typed exception carrying the envelope
**verbatim**, extras included:

```python
from policyvault_client import ScopeError, ApiError

try:
    pv.build_request(spec)
except ScopeError as e:
    e.status, e.code, e.message      # 403, "SCOPE_FORBIDDEN", "…request:build…"
except ApiError as e:
    e.envelope                       # the server's error object, unmodified
    e.extra                          # route-specific extras: request, intent, …
    e.replayed                       # was this an idempotent replay?
```

| class | when |
|---|---|
| `ValidationError` | refused locally; nothing was sent |
| `TransportError` | no response (DNS/connect/TLS/timeout) |
| `ProtocolError` | a response that is not a well-formed PolicyVault answer, or a redirect |
| `AuthenticationError` | 401 |
| `ScopeError` | 403 (`SCOPE_FORBIDDEN`, `ORIGIN_REQUIRED`, …) |
| `NotFoundError` | 404 — also how a *foreign* object is hidden |
| `ConflictError` / `IdempotencyConflictError` / `IdempotencyInProgressError` | 409 |
| `SchemaVersionError` / `UnprocessableError` | 422 |
| `RateLimitError` | 429 |
| `ServerError` | 5xx — transient; an idempotency claim is released |

---

## Transport decisions worth knowing

* **Redirects are refused.** `urllib` would otherwise follow a 3xx and re-send
  the `Authorization` header to whatever host it names.
* **Environment proxies are ignored** unless you pass `trust_env_proxy=True`.
* **No CORS, no cookies.** In hosted mode a *cookie-free bearer* request is
  exempt from the browser CSRF/origin wall. An **unauthenticated** POST from a
  programmatic client is therefore refused at the origin wall
  (`403 ORIGIN_REQUIRED`) rather than at authentication — so a machine client
  must always present a credential.
* Responses are capped at 8 MiB; bodies must be JSON objects.

---

## Tests

Run from `python/`:

```bash
python3 -m unittest discover -s tests -t .          # all 75
python3 -m unittest discover -s tests -t . -v       # verbose
python3 -m unittest tests.test_amounts              # one module
```

`pytest` is not required (and is not installed on the reference machine);
if present it collects the same `unittest.TestCase` classes unchanged.

| module | layer | tests |
|---|---|---|
| `test_amounts.py` | UNIT | 19 — parser-rule parity with the vectors from `sdk/test/amounts.test.js`, plus Python-specific hazards |
| `test_schemas.py` | UNIT | 16 — closed schemas, lexical shape, amount hygiene at the boundary |
| `test_secret_redaction.py` | UNIT | 12 — the token never escapes; no logging sink; stdlib-only imports |
| `test_live_server.py` | INTEGRATION | 28 — **real HTTP against the real Node server** |

The integration suite has **no mock server**. `tests/_server_boot.js` starts
`server/src/server.js` `createServer(config)` from this worktree on an
ephemeral loopback port with the JSON backend, seeds one v0.4 vault manifest,
and mints two machine credentials (full-scope and read-only) through a real
hosted wallet session — the one thing a stdlib-only Python client cannot do for
itself, and by design must not be able to.

**Environment note.** The v0.4 builder shells out to the real Rust probes under
the gitignored `tests/vm/target/debug/`. Without them the build-dependent tests
**skip** with an explicit remedy rather than failing:

```bash
cd tests/vm && cargo build --bin pv_call_encoder --bin pv_tx_probe
```

In a git *worktree* Cargo cannot resolve the sibling `../../../silverscript`
path, so link an existing build into `tests/vm/target/debug/` instead.

---

## License

Apache-2.0 — the license the owner selected for PolicyVault. Free forever,
including commercial use; no subscriptions, no fees, no paid feature or
security gates, ever. Voluntary KAS support only.
