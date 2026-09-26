# Idempotency inspection and recovery

An idempotency key protects the original attempt permanently. A delayed
handler, failed request, missing acknowledgement or old timestamp does not
establish that no effect occurred. Never delete a claim, change its owner,
change the request key, or replay a handler to resolve uncertainty. Creating
a new key can create a second operation; it is not a recovery procedure.

## Supported local workflow

`server/src/idempotency.js` exports `inspectIdempotency(config, originalArgs)`
and `recoverIdempotency(config, originalArgs)` for a trusted implementation or
operator environment. These are not HTTP routes and do not authenticate a
caller. Use the already-authorized configuration and open SDK store, with the
same network/data root and exact original authenticated principal, raw key,
method, path segments, query and body. Restrict that environment and request
material to the appropriate operator/tenant. The functions do not establish
billing-account membership or permission to perform an underlying operation.
No production maintenance is authorized by this local remediation.

```js
const { inspectIdempotency, recoverIdempotency } = require("./server/src/idempotency");
const state = await inspectIdempotency(config, originalArgs);
if (state.recoverable) await recoverIdempotency(config, originalArgs);
```

Inspection returns only state, recoverability, legacy status and timestamps.
It does not return the original request, response, credentials or receipt.
It does not dispatch a handler or write records. Recovery accepts no handler,
replacement response, reset command or financial proof. It can only finalize
the exact receipt already embedded in the matching claim. Afterwards, a
normal authorized matching request returns the retained response. The usual
route authentication and scope checks still run before the wrapper.

| Inspection result | Supported action |
| --- | --- |
| `ABSENT` | No claim is visible in this configured store. Establish that configuration and domain state are correct; absence is not a financial outcome or a replay authorization. |
| `IN_PROGRESS`, no receipt | Preserve the claim. The handler may still be active or may have stopped. Inspect domain operation records; age is not a lease. |
| `UNRESOLVED` | Preserve the claim and domain reservations. A handler error did not establish its effect. |
| `COMPLETION_AVAILABLE` | `recoverIdempotency` may finalize the retained receipt without reexecuting the operation. |
| `COMPLETE` | A matching authorized request can replay the retained response. This records the handler response, not independent confirmation of an on-chain or financial outcome. |
| Conflict, malformed data or unavailable read | Preserve the records and investigate the binding or storage failure. No reset or replay is performed. |

If the handler stopped after an effect but before a completion receipt was
persisted, generic recovery cannot reconstruct the response. This limitation
also applies to legacy unfinished claims with no owner identifier/receipt.
Domain-specific reconciliation must inspect durable operation identity and
outcome evidence. No generic “safe to retry” override or arbitrary outcome
injection is supported. The implementation owner must provide and verify a
narrow domain repair if a complete response cannot be established. An
unresolved operation is not marked complete merely to restore availability.

## Persistence and concurrency

New records retain schema `policyvault-idempotency-record/v1` and add an
immutable random claim owner and an embedded
`policyvault-idempotency-completion/v1` receipt. The receipt binds network,
composite scope/key, request fingerprint, owner, original creation time and
exact definitive response. No additional row, category, response endpoint or
migration is introduced. The completion response is also retained in the
legacy `response` field, increasing storage per completed claim. Required
claim/receipt evidence must remain in durable private storage and backups;
there is no automatic expiry or cleanup in this correction.

PostgreSQL uses a conditional UPDATE against the whole expected jsonb record,
network and key; it never inserts from a completion operation. Concurrent
connections cannot replace another owner's claim or a completed record.
JSON uses a synchronous current-record comparison and durable write under the
existing single service-writer contract. Multiple independent JSON writer
processes sharing a data root are unsupported; use PostgreSQL for those
workloads. Local maintenance must observe that same JSON writer boundary.
The exclusive initial JSON claim remains a filesystem create-only operation.

A lost create acknowledgement returns uncertainty without invoking the
handler. A lost prepare or completion acknowledgement can be resolved only
by exact durable readback. If readback is unavailable, callers receive
`IDEMPOTENCY_OUTCOME_UNKNOWN` and the claim remains protected. A later request
or maintenance call can finish a retained receipt, including after process
restart. No receipt means no generic recovery. A deterministic 4xx refusal is
retained and replayed; a no-status/5xx error is not evidence of no effects.

Original v1 records with no `claimId`, `completionReceipt` or `outcomeState`
field retain legacy compatibility: complete records replay their historical
response, and unfinished records remain protected indefinitely. Presence of
any new-format field requires a valid claim owner, including when a field is
null, empty or otherwise falsy. Any present receipt must validate; a malformed
new record is not adopted as legacy by replay, inspection or recovery.
This structural distinction relies on trusted durable storage: a record whose
new-format fields were all removed is indistinguishable from an original
legacy record. No cryptographic legacy provenance is claimed.
The new code requires no schema beyond the historical schema 005 category;
its schema-11 and development-schema checks are synthetic compatibility
checks. Stop older service writers before adopting the corrected runtime:
older code can still delete aged unfinished records, so running mixed
versions or rolling back only the image does not preserve these guarantees.
Database/schema compatibility alone does not qualify an old runtime rollback.

The scope assumes trusted application/storage writers and authentic durable
storage. Raw operator table/file edits, claim removal, restored older backups
or running an old writer can violate that boundary. Tests inject a privileged
replacement to prove a late conditional completion refuses to overwrite it;
that injection is not a supported way to replace a real claim.

## Verification boundary

`server/test/idempotency-safety.test.js` exercises delayed real handlers with
an advanced clock, durable synthetic effects before errors, different-input
collisions, concurrent claims/conditional updates, receipt tampering,
lost acknowledgements, legacy states and recovery from a fresh process.
Its PostgreSQL path requires a dedicated private cluster on
`127.0.0.1:55438`, role `idempotency_review`, control database `postgres`;
it refuses other destinations before connecting. It creates and drops only
randomly named owned databases and verifies the exact database census. Run
multiple database-census suites with `--test-concurrency=1` by file; each
suite still exercises its explicit concurrent requests and database updates.
The JSON tests execute with PostgreSQL settings absent. Existing real API,
credential and platform-store suites remain applicable.

RC42 contained the same pre-correction idempotency implementation as the
reviewed development checkpoint. That confirms source applicability of the
races; it does not invent a production incident or change historical
acceptance records. The schema-011 successor of RC42 carries this correction;
its independent review and release qualification are recorded in its release
records. No billing activation or financial operation is involved.
