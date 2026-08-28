# Instant hosted-layer agent suspend (fullscale surface 21 residual)

**Status: IMPLEMENTED + UNIT-TESTED** (API layer; JSON + PostgreSQL
backends; release-candidate lane — NOT part of the frozen production
artifact `phaseg-rc2`). Branch `fs-residuals`. Tests:
`sdk/test/postlaunch-agent-suspend-server.test.js` (14/14 with live PG —
13 JSON + 1 PG migration/round-trip).

**Web UI: COMPOSED (W4-refinements, branch `fs-refinements`) +
BROWSER-TESTED** (`web/app-v4.js` + `web/test/app-v4-agent-suspend.
test.js`, 13 tests in the headless vm harness): per-agent and all-agents
suspend/unsuspend buttons against the existing routes with
`expectedVersion` CAS; the state banner renders `NOT_COVENANT_NOTICE`
VERBATIM (the test pins the rendered text against THIS module's exported
constant) next to the covenant Pause control; SUSPENDED (hosted) badge
visible to every participant; stale suspended keys get inline unsuspend
affordances; FAIL-CLOSED rendering (an unloadable/unrecognized state
renders UNKNOWN and disables the flip controls — never "not suspended");
server 403/404/VERSION_CONFLICT surface verbatim. Not
human-acceptance-tested.

## 1. What it IS — and, first, what it is NOT

**NOT A COVENANT CONTROL.** A suspension makes the PolicyVault server
refuse NEW agent-driven work instantly (0 fees, no chain interaction).
It does not and cannot bind the covenant: a malicious actor holding the
legitimate delegate key can still construct and submit transactions
directly to a Kaspa node, and only the covenant's consensus rules
constrain those. The covenant-enforced controls remain the security
boundary and the only controls that hold against that adversary:

| Need | Covenant control (the boundary) | Hosted suspend (this feature) |
|---|---|---|
| Stop ALL spending, enforced on-chain | `ownerPause` (break-glass; ungateable) | — |
| Remove an agent's authority, enforced on-chain | `removeAgent` / `ownerSetAgentRoot` | — |
| Terminal recovery | `ownerRecover` (break-glass) | — |
| Instantly stop the HOSTED pipeline serving an agent (while deciding / while the on-chain action confirms) | — | suspend (instant, free, reversible) |

Every API response and every refusal carries this statement verbatim
(`NOT_COVENANT_NOTICE`, `server/src/agent-suspensions.js`), pairing the
control with the covenant pause guidance ("For covenant-enforced
protection, pause the vault or remove the agent"). Nothing in copy or
logic treats a suspension as satisfying, replacing, or weakening
covenant pause — tested (`copy/logic sweep` case; the vault's covenant
`paused` field is untouched; `ownerPause` still builds while a
suspension is active).

Why it exists anyway: well-behaved agents/integrations transact THROUGH
the hosted pipeline, so cutting that pipeline stops a misbehaving-but-
honest automation (runaway loop, compromised orchestration ABOVE the
key, mistaken policy) in ~0 seconds at zero cost, while the owner
decides whether an on-chain action (fee-bearing, ~seconds) is warranted.

## 2. Surface

- **Record** (migration `007_agent_suspensions.sql`; platform-store
  category `AGENT_SUSPENSION`, key = vaultId):
  `policyvault-agent-suspensions/v1` `{ vaultId, networkId, version,
  allAgents, agents[] (sorted unique x-only), updatedAt, updatedBy
  {type: wallet|machine|operator, identityId|null} }` — expectedVersion
  CAS (org-controls discipline). A CORRUPT/unknown stored record FAILS
  CLOSED in the RESTRICTIVE direction: agent builds refuse
  (`SUSPENSIONS_SCHEMA_UNKNOWN`) rather than silently reading as "not
  suspended" (tested).
- **Routes** (`server/src/api.js`):
  - `GET /api/v1/vaults/:vaultId/agent-suspensions` — vault-participant
    read (agents can SEE they are suspended); scope `read:vaults`.
  - `POST` same path `{ op: "suspend"|"unsuspend", agentPk | allAgents:
    true, expectedVersion? }` — vault-OWNER tenancy (wallet session, or
    a machine identity that BOTH inherits the owner wallet's tenancy AND
    holds the dedicated deny-by-default scope `vaults:suspend-agents`).
    Suspending an unknown key refuses (`AGENT_UNKNOWN` — typo
    fail-closed); unsuspend stays permissive for stale keys (clearable
    after removeAgent/rotate). Audited (`agent_suspension_updated`) and
    evented (`vault.agent.suspended` / `.unsuspended`, closed catalog —
    webhooks-events-spec §4.5). Capabilities: feature
    `hostedAgentSuspend`, schema, scope description.
- **Enforcement** (agent-ROLE actions only; owner ops — including
  break-glass — are never touched):
  - build (`POST /wallet/v4/requests`) — refused BEFORE any durable
    work (pure refusal);
  - finalize (`.../signature`) and submit (`.../submit`) — a request
    built BEFORE the suspension can neither finalize nor broadcast
    while suspended;
  - dry-run (`POST /wallet/v4/simulate`) reports the SAME refusal
    (`ok:false`, never `ok:true` for an operation the real route
    refuses).
  The acting agent is attributed by every identity the stage can see
  (params/request `agentPk` + the resolved signer wallet); any match
  refuses `403 AGENT_SUSPENDED_HOSTED` with the covenant-honesty notice
  in the message and `extra.suspension`.

## 3. Hostile coverage (each with a test)

Suspended agent's new build refused; pre-suspension BUILT request
refused at finalize AND submit; simulation honesty; per-agent isolation
(other agent unaffected); all-agents suspend/unsuspend; unsuspend
restores immediately; CAS conflict 409; unknown-agent suspend 422;
malformed op/selectors 400; corrupt stored record fails RESTRICTIVE
(then repairable); machine identity without the scope
`SCOPE_FORBIDDEN`; truly-foreign machine identity 404 (existence
hidden); participant-not-owner 403 `VAULT_FORBIDDEN`; suspended agent's
own machine credential still SEES the suspension but cannot flip it;
covenant `paused` untouched + `ownerPause` still builds (suspend never
satisfies or replaces covenant pause); PG: migration 007 applies after
001–006 and the store round-trips + enforces through the real server.

## 4. Honest limits / remaining

- Coordination only (see §1) — by design, stated everywhere.
- Browser UI controls (buttons on the vault view) are NOT part of this
  wave: the API + copy are complete; UI composition belongs to the
  web-composition owner. The UI MUST reuse `NOT_COVENANT_NOTICE`
  verbatim next to any suspend control and never render a suspension as
  "paused".
- Approval COLLECTION on a suspended agent's pending above-threshold
  request is not blocked (approvers are not the suspended principal);
  the request still cannot finalize or submit while suspended.
