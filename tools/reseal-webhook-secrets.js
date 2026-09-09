"use strict";

/*
 * tools/reseal-webhook-secrets.js — operator-run migration step for a
 * POLICYVAULT_WEBHOOK_SECRET_KEY rotation
 * (docs/postlaunch/webhook-secret-rotation-procedure.md, TRACK 9).
 *
 * BACKGROUND (server/src/webhooks.js module header): each webhook
 * endpoint's per-tenant HMAC secret is stored as an "aes256gcm/v1"
 * envelope sealed under whatever POLICYVAULT_WEBHOOK_SECRET_KEY was
 * current at mint/rotation time. Simply swapping that env var to a new
 * value makes every already-stored envelope permanently undecryptable
 * under the new key alone. The rotation procedure sets the OPTIONAL
 * POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS fallback during a bounded
 * grace window so deliveries keep working, then runs THIS tool to
 * re-seal every endpoint's secret (and any still-live previous-secret,
 * from the UNRELATED per-endpoint rotation grace in webhooks.js
 * rotateEndpointSecret) under the CURRENT key only — after which
 * POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS can be safely removed again.
 *
 * Idempotent and safe to re-run: an envelope already sealed under the
 * current key is simply re-sealed again (a fresh random IV/ciphertext,
 * same plaintext) — wasted work, never a correctness or security issue.
 * This tool never touches "plain/v1" envelopes (nothing to migrate —
 * there is no at-rest key in that mode) and never touches anything if
 * POLICYVAULT_WEBHOOK_SECRET_KEY is unset (there would be nothing valid
 * to reseal onto).
 *
 * DEFAULT IS A DRY RUN — pass --apply to actually write. Designed to run
 * the same way the one-shot `migrate` service does (see
 * deploy/docker-compose.prod.yml): inside the application image, against
 * the SAME configuration the app itself uses, e.g.
 *   docker compose -f docker-compose.prod.yml --env-file prod.env \
 *     run --rm --entrypoint node app tools/reseal-webhook-secrets.js --apply
 * This tool is never invoked automatically by anything in this
 * codebase — it is a documented, deliberate operator step.
 */

const { loadConfig } = require("../sdk/src/config");
const { openPgStore } = require("../sdk/src/store");
const { Categories, getEventsStore } = require("../server/src/events-store");
const wh = require("../server/src/webhooks");

/*
 * Walks every stored webhook endpoint (any status — revoked endpoints'
 * secrets are migrated too, so nothing is left permanently dependent on
 * a retired key) and re-seals its `secret` and, if present, its
 * still-recorded `previousSecret` (the per-endpoint rotation-grace
 * field — unrelated to POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS) under
 * whichever key `server/src/webhooks.js sealSecret()` currently
 * considers CURRENT. Returns a report; writes only when `apply` is
 * true. Never throws for an individual endpoint's failure — failures
 * are collected in the report so one bad envelope never aborts the
 * whole run.
 */
async function resealAll({ config, apply = false }) {
  const store = getEventsStore(config);
  const all = await store.listValues(Categories.WEBHOOK_ENDPOINT);
  const report = { apply, totalEndpoints: all.length, aes256gcmSecrets: 0, plainSecrets: 0, resealed: 0, failed: [] };

  for (const endpoint of all) {
    if (!endpoint || typeof endpoint.endpointId !== "string" || !endpoint.secret) continue;
    let changed = false;
    const updated = { ...endpoint };

    if (endpoint.secret.v === "aes256gcm/v1") {
      report.aes256gcmSecrets++;
      try {
        updated.secret = wh.resealSecret(endpoint.secret);
        changed = true;
      } catch (e) {
        report.failed.push({ endpointId: endpoint.endpointId, field: "secret", error: e.message });
      }
    } else if (endpoint.secret.v === "plain/v1") {
      report.plainSecrets++;
    }

    if (endpoint.previousSecret && endpoint.previousSecret.v === "aes256gcm/v1") {
      try {
        updated.previousSecret = wh.resealSecret(endpoint.previousSecret);
        changed = true;
      } catch (e) {
        report.failed.push({ endpointId: endpoint.endpointId, field: "previousSecret", error: e.message });
      }
    }

    if (changed) {
      report.resealed++;
      if (apply) await store.write(Categories.WEBHOOK_ENDPOINT, endpoint.endpointId, updated);
    }
  }
  return report;
}

if (require.main === module) {
  (async () => {
    const apply = process.argv.includes("--apply");
    const config = loadConfig({ allowMainnet: process.env.POLICYVAULT_ALLOW_MAINNET === "true" });
    if (config.persistenceBackend === "postgres") await openPgStore(config);
    const report = await resealAll({ config, apply });
    console.log(JSON.stringify(report, null, 2));
    if (!apply) console.error("\nDRY RUN — no writes performed. Re-run with --apply to write resealed envelopes.");
    if (report.failed.length) {
      console.error(`\n${report.failed.length} endpoint secret(s) could not be opened under the current or previous key — needs manual attention before removing POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS.`);
      process.exit(1);
    }
  })().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}

module.exports = { resealAll };
