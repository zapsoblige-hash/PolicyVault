# Webhook At-Rest Secret Key (`POLICYVAULT_WEBHOOK_SECRET_KEY`) Rotation Procedure

TRACK 9 (release signing + succession governance). Status: **DESIGNED +
IMPLEMENTED + UNIT-TESTED**. **This procedure has NOT been executed under
this track.** No production infrastructure was touched to write this
document or its supporting code (`server/src/webhooks.js`'s
`POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS` fallback,
`tools/reseal-webhook-secrets.js`) — everything here was designed and
tested locally against the JSON store backend. Running this procedure for
real, on the production droplet, is an OWNER-ONLY action for a future
controlled successor deployment (§9).

## 1. Which secret this is (and which it is NOT)

This document covers exactly one secret: **`POLICYVAULT_WEBHOOK_SECRET_KEY`**
— the optional 64-hex (32-byte) operator key that, when set, encrypts every
webhook endpoint's HMAC signing secret at rest with AES-256-GCM
(`server/src/webhooks.js sealSecret`/`openSecret`,
`docs/postlaunch/webhooks-events-spec.md` §7). It protects **database
dumps/backups leaving the host** — it does NOT protect against a fully
compromised application host, which must read the plaintext secret at
every delivery regardless (documented honestly in both the code and the
spec; this document does not repeat or weaken that limitation).

**This is NOT the same secret as:**

- A **per-endpoint webhook HMAC secret** (`pvwh_…`, shown once at
  `POST /webhooks` or `POST /webhooks/:id/rotate-secret`). Those already
  have their OWN complete, tested, self-service rotation mechanism —
  `docs/postlaunch/webhooks-events-spec.md` §6, §8: rotate via the API,
  the previous secret co-signs deliveries for a 24 h grace window, no
  operator/droplet action is ever needed. **This document does not
  duplicate that — it is already solved.** It matters here only as
  something this rotation must not break (§2, §6).
- A **release-signing key** (`tools/release-sign.js`,
  `docs/postlaunch/release-trust-model.md`) — an unrelated key, unrelated
  purpose, from the same TRACK 9 engineering session only by coincidence.
- The **hosted session/auth signing material** or any covenant/signer key
  — this document never touches funds-authority key material of any kind.

## 2. Why `POLICYVAULT_WEBHOOK_SECRET_KEY` rotation is not trivial

**Naively swapping the env var value breaks every active webhook
endpoint.** The at-rest envelope carries no key identifier — `openSecret`
tried exactly one key (whatever `POLICYVAULT_WEBHOOK_SECRET_KEY` currently
is). If that value changes, every already-stored `"aes256gcm/v1"` envelope
becomes undecryptable under the new key, and **every subsequent delivery
attempt for every affected endpoint fails closed**
(`WEBHOOK_SECRET_UNAVAILABLE`) — safely (no plaintext fallback, no forged
signature), but a real availability regression for every webhook consumer
until fixed. This was verified directly while building this track (see
`sdk/test/postlaunch-webhooks-events.test.js`'s pre-existing "wrong key
fails closed" regression test).

**This is why this document does not describe "generate a new value and
overwrite the env file" as a one-step operation.** It describes the
additive fix built for this track instead (§3) and the exact atomic
procedure that uses it (§5).

## 3. The fix: an explicit, bounded fallback key + a migration tool

Two additive, fully-tested, zero-default-behavior-change pieces (both
already implemented on this branch):

1. **`POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS`** (optional, same 64-hex
   shape) — `openSecret` in `server/src/webhooks.js` now tries the
   CURRENT key first and, only on failure, falls back to this env var if
   it is set. **Unset (the default), behavior is byte-for-byte identical
   to before this change** — including the pre-existing "wrong key fails
   closed, no fallback" test, which still passes unmodified. Sealing
   (minting/rotating a per-endpoint secret) always uses the current key
   only — this fallback is a READ-time convenience during a deliberate
   rotation window, never a write-time behavior change.
2. **`tools/reseal-webhook-secrets.js`** — an operator-run migration tool
   (dry-run by default; `--apply` to write) that walks every stored
   webhook endpoint and re-seals its secret (and, if present, its
   still-live per-endpoint `previousSecret` — the UNRELATED §1 rotation
   grace field) under the CURRENT key only, using the same
   current-then-previous fallback to open each one first. After a
   successful `--apply` run with zero `failed` entries,
   `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS` is no longer needed by
   anything and can be removed. It never runs automatically — it is
   invoked deliberately, the same way the existing one-shot `migrate`
   service is (`deploy/docker-compose.prod.yml`).

Together these turn "rotate the at-rest key" from a step that breaks
active endpoints into: **set both keys → confirm deliveries still work →
migrate → confirm nothing needs the old key → remove the old key** — an
ordinary, bounded, zero-downtime rotation.

## 4. Every consumer of this secret's VALUE

| Consumer | What it does with the value | Restart/action needed on rotation |
|---|---|---|
| `server/src/webhooks.js` (`atRestKey`, `previousAtRestKey`, `sealSecret`, `openSecret`) | Reads `process.env.POLICYVAULT_WEBHOOK_SECRET_KEY` (+ optionally `_PREVIOUS`) at every endpoint create/rotate and at every delivery attempt (via `signingSecretsFor` → `openSecret`, called from `server/src/events-delivery.js` before `server/src/events-signing.js signWebhookPayload` HMAC-signs the outbound body) | Needs the NEW value; the running Node process only re-reads `process.env` when it restarts — a container restart is required (§5), not merely an env-file edit |
| `deploy/prod.env` (on the production droplet, root:root, mode 600) | The ONLY place the value is configured/stored outside the running process's memory | The single privileged edit target (§5) |
| `deploy/docker-compose.prod.yml` | `app` and `migrate` both declare `env_file: [prod.env]`, so both containers receive whatever is in the file; `cloudflared` does NOT (no `env_file` entry) | Only `app` needs restarting (it is the only one that ever calls `openSecret`/`sealSecret`); `migrate` is a one-shot, manually-invoked service unrelated to this key and needs no re-run; `cloudflared` is entirely unaffected |
| `tools/reseal-webhook-secrets.js` (new, §3) | Reads both env vars to perform the migration | Run once per rotation, inside the `app` image/environment, after the restart in §5 |
| Docker/DB backups (`docs/hosted-backup-restore.md`) | `pg_dump` backups of `webhook_endpoints` contain the SEALED CIPHERTEXT envelopes, never the at-rest key itself (the key lives only in the env file, never in the database) | An old backup remains readable only by whoever also has the OLD key from that time — this is normal and does not need "fixing" as part of a routine rotation; it only matters if the OLD key itself is suspected compromised (treat as key compromise, not routine rotation — apply extra urgency to §5–§6, and consider whether historical backups containing endpoint secrets need separate handling per your backup-retention policy) |
| Any droplet-level config/disk backup or snapshot that happens to capture `/opt/policyvault/prod.env` itself | This is the one place a snapshot could capture the RAW KEY VALUE (not just ciphertext) | Out of this document's direct control (it is a property of whatever backup system the droplet uses) — §5's privileged-command discipline keeps the value out of shell history/logs/chat; the org's normal snapshot-retention/deletion policy governs anything that already captured a retired `prod.env` |
| Webhook consumer verifiers (JS reference recipe in `docs/postlaunch/webhooks-events-spec.md` §8, and the new `python_client.verify_webhook_signature`, `python/policyvault_client/webhooks.py`) | Verify deliveries using the PER-ENDPOINT `pvwh_…` secret (§1) — **never** `POLICYVAULT_WEBHOOK_SECRET_KEY`, which structurally never leaves the server | **Unaffected by this rotation.** A consumer's own configured secret keeps working throughout — see §7 for why "post-rotation verification" still makes sense despite this |

## 5. Atomic update procedure

**Precondition:** a verified `pg_dump -Fc` backup of `policyvault_prod`
taken per the standing discipline in `docs/hosted-backup-restore.md` /
`docs/postlaunch/promotion-readiness-packet.md` §2 — not required for THIS
key's own correctness, but the project's standing practice before any
production database-adjacent maintenance.

1. **Generate the new key and stage both values into the env file with a
   single privileged command that never prints either value to the
   terminal, shell history, or any log.** On the droplet, as the
   privileged operator:

   ```bash
   sudo install -m 600 /dev/null /root/rotate-webhook-key.sh
   sudo tee /root/rotate-webhook-key.sh > /dev/null <<'SCRIPT'
   #!/usr/bin/env bash
   set -euo pipefail
   ENV_FILE=/opt/policyvault/prod.env
   TS=$(date -u +%Y%m%dT%H%M%SZ)
   BACKUP="${ENV_FILE}.pre-webhook-key-rotation-${TS}"
   install -m 600 "$ENV_FILE" "$BACKUP"
   OLD_KEY=$(grep -E '^POLICYVAULT_WEBHOOK_SECRET_KEY=' "$ENV_FILE" | cut -d= -f2- || true)
   NEW_KEY=$(openssl rand -hex 32)
   # Set the new current key.
   if grep -q '^POLICYVAULT_WEBHOOK_SECRET_KEY=' "$ENV_FILE"; then
     sed -i "s/^POLICYVAULT_WEBHOOK_SECRET_KEY=.*/POLICYVAULT_WEBHOOK_SECRET_KEY=${NEW_KEY}/" "$ENV_FILE"
   else
     echo "POLICYVAULT_WEBHOOK_SECRET_KEY=${NEW_KEY}" >> "$ENV_FILE"
   fi
   # Preserve the retiring key as the explicit, bounded fallback.
   if [ -n "$OLD_KEY" ]; then
     if grep -q '^POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS=' "$ENV_FILE"; then
       sed -i "s/^POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS=.*/POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS=${OLD_KEY}/" "$ENV_FILE"
     else
       echo "POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS=${OLD_KEY}" >> "$ENV_FILE"
     fi
   fi
   chmod 600 "$ENV_FILE"
   echo "rotated. previous env backed up at ${BACKUP} (mode 600). NEITHER key value was printed above."
   SCRIPT
   sudo chmod 700 /root/rotate-webhook-key.sh
   sudo /root/rotate-webhook-key.sh
   ```

   Every step here runs inside one non-interactive script: the new key is
   generated with `openssl rand -hex 32` and the old key is read straight
   from the file, both entirely inside `sed`/shell-variable substitutions
   that never echo to stdout, so neither value ever appears in the
   terminal transcript, shell history, or (if this is pasted into a chat
   session to construct the script) the chat itself — only the SCRIPT
   LOGIC (which contains no secret material) does. The script itself can
   be left in place (`/root`, mode 700, root-only) for the next rotation,
   or deleted — its logic carries no secret.

2. **Restart ONLY the app container** (never `migrate`, never
   `cloudflared` — §4):

   ```bash
   docker compose -f /opt/policyvault/docker-compose.prod.yml \
     --env-file /opt/policyvault/prod.env up -d app
   ```

   Wait for the container to report healthy
   (`docker compose ps`, and `/api/v1/health/ready` — the real readiness
   check, DB reachable + schema current + network stamp, per
   `docs/postlaunch/promotion-readiness-packet.md` §3, §5). At this point
   every delivery for every existing endpoint succeeds via the
   `_PREVIOUS` fallback (§3 above); nothing is broken, but nothing is
   migrated yet either.

3. **Run the migration tool** inside the same image/environment:

   ```bash
   docker compose -f /opt/policyvault/docker-compose.prod.yml \
     --env-file /opt/policyvault/prod.env \
     run --rm --entrypoint node app tools/reseal-webhook-secrets.js
   ```

   (`--entrypoint` takes a single executable, no arguments — `node` — and
   everything after the service name (`app`) becomes the command appended
   to it, exactly the `migrate` service's own documented pattern in
   `deploy/docker-compose.prod.yml`: "MUST override the image ENTRYPOINT,
   not `command:` — compose `command` is APPENDED to the entrypoint.")

   Review the report (`resealed`, `failed`). If `failed` is non-empty,
   **do not remove `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS` yet** —
   investigate those specific endpoint ids first (§8). Re-run with
   `--apply` appended once satisfied with a dry run, or always run with
   `--apply` directly — it is idempotent either way.

4. **Confirm `failed` is empty**, then remove
   `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS` with the same
   never-print-the-value discipline as step 1 (a `sed -i '/^POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS=/d' /opt/policyvault/prod.env`, back up the env file first exactly as in step 1), and restart the
   app container once more.

5. **Run §7's post-rotation verification** before considering the
   rotation complete.

## 6. Rollback

- **Before step 2 (app not yet restarted):** trivial — the running
  container is untouched; delete or ignore the edited env file; nothing
  changed for real. No further action.
- **After step 2 but before step 3 (app restarted onto the new key, no
  reseal run yet):** restore the exact backed-up env file from step 1
  (`cp <backup> /opt/policyvault/prod.env`, preserving mode 600) and
  restart the app container again. Every endpoint's secret is still
  sealed under the ORIGINAL key only, so this is a full, lossless
  rollback — the `_PREVIOUS` fallback was never exercised for a real
  write, only for reads.
- **After step 3 has resealed at least one endpoint:** **do not merely
  restore the old env file** — some endpoints are now sealed under the
  NEW key, and a straight revert would make those specific endpoints
  fail exactly the way §2 describes, just with the roles reversed. The
  correct rollback here is to **swap which key is "current" and which is
  "previous"** (old key becomes `POLICYVAULT_WEBHOOK_SECRET_KEY`, new key
  becomes `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS`), restart, and either
  (a) run `tools/reseal-webhook-secrets.js --apply` again to migrate
  everything back onto the old key, or (b) simply decide to keep going
  forward instead of rolling back once you are past this point — a
  partially-completed reseal is never an outage, only a still-necessary
  `_PREVIOUS` dependency, so "roll forward" is usually the better choice
  once step 3 has actually started succeeding.
- **The DB backup from the precondition** is the last-resort path if
  something goes wrong with the `webhook_endpoints` table itself (not
  merely the key) — restore per `docs/hosted-backup-restore.md`, which
  already documents that a database restore never rolls back Kaspa chain
  truth and is unrelated to any covenant/funds state.

## 7. Post-rotation verification (by the operator, secret never enters chat)

The at-rest key itself is structurally unverifiable from outside the
server (§4's last row) — proving the rotation worked means proving the
server can still **produce valid, verifiable signed deliveries**
end-to-end. Procedure:

1. On the now-rotated production app, mint a **fresh** per-endpoint
   webhook secret — either create a new test endpoint
   (`POST /webhooks`) or rotate an existing one you control
   (`POST /webhooks/:id/rotate-secret`). Either call returns a new
   `pvwh_…` secret shown exactly once, in the API response, to the
   operator making the call — this is the "NEW secret" referred to
   below, and it never needs to be typed into, or appear in, any chat
   session; the operator copies it directly from their own terminal/API
   client into their own verification step.
2. Trigger any real, low-risk event that endpoint is subscribed to (or
   simply wait for organic traffic if the endpoint already existed) —
   there is no synthetic "send a test event" route today (a reasonable
   future enhancement, out of scope for this track).
3. At the operator's own receiver (whatever already logs/handles
   incoming webhook requests), capture the exact received
   `X-PolicyVault-Signature` header and the exact raw request body bytes
   for one delivery.
4. Verify it **locally**, using either reference verifier, against the
   NEW per-endpoint secret from step 1 — never against
   `POLICYVAULT_WEBHOOK_SECRET_KEY` itself, which no verifier ever takes
   as input:

   ```js
   // Node / JS — docs/postlaunch/webhooks-events-spec.md §8
   const { verifyWebhookSignature } = require("server/src/events-signing");
   // or the standalone snippet published in that doc, which needs no
   // PolicyVault source at all.
   const result = verifyWebhookSignature({ header, rawBody, secret: newPvwhSecret });
   console.log(result); // expect { ok: true, timestampSeconds: ... }
   ```

   ```python
   # Python — python/policyvault_client/webhooks.py
   from policyvault_client import verify_webhook_signature
   result = verify_webhook_signature(header=header, raw_body=raw_body, secret=new_pvwh_secret)
   assert result.ok, result.reason
   ```

5. `ok: True`/`{ ok: true }` proves: the server successfully decrypted a
   per-endpoint secret (meaning `openSecret` — and therefore the
   rotated `POLICYVAULT_WEBHOOK_SECRET_KEY`, possibly still via the
   `_PREVIOUS` fallback if step 4 of §5 has not run yet) and used it to
   correctly HMAC-sign a real delivery, and that an independent verifier
   agrees. This is the complete, real, end-to-end confirmation that the
   rotation has not broken webhook delivery.

## 8. Investigating a `failed` entry from the migration tool

`tools/reseal-webhook-secrets.js`'s report lists any endpoint whose secret
could not be opened under EITHER the current or the previous key. This
means that endpoint's secret was sealed under some THIRD, no-longer-
configured key — almost always evidence of an earlier, incomplete
rotation (a previous `_PREVIOUS` value was removed before every endpoint
had been migrated onto it). Recovery options, in order of preference:

1. If the earlier retired key value is still known/recoverable (e.g. from
   the timestamped `prod.env.pre-webhook-key-rotation-*` backup files
   §5 leaves behind), temporarily set it as
   `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS`, restart, re-run the tool,
   then return to the intended current/previous pair.
2. If it is truly unrecoverable, that endpoint's secret is permanently
   lost — the endpoint owner must rotate it themselves
   (`POST /webhooks/:id/rotate-secret`, an ordinary self-service
   operation unrelated to the at-rest key) to mint a fresh secret sealed
   under the current key.

## 9. This procedure is bundling-ready, not executed

Everything in this document is designed to be folded into a controlled
successor deployment packet (the same shape as
`docs/postlaunch/promotion-readiness-packet.md`) whenever the owner
decides to actually rotate this key — the config diff is exactly
`POLICYVAULT_WEBHOOK_SECRET_KEY` (+ a transient `_PREVIOUS` during the
window), the restart scope is `app` only (§4), and the additive code
(§3) has zero effect on any deployment that never sets
`POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS`. **Nothing in this track ran any
part of §5 against the real droplet, the real database, or the real
`prod.env` file** — this is a designed, locally-tested (JSON-backend)
procedure and tool, not an executed operation. Executing it is an
owner-only future action, same as every other production-infrastructure
change in this project (`CLAUDE.md` "SOURCE CHANGE ≠ AUTOMATIC LIVE
DEPLOYMENT").
