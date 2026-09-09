"use strict";

/*
 * UNIT/INTEGRATION — tools/reseal-webhook-secrets.js (TRACK 9 webhook
 * secret rotation procedure; docs/postlaunch/webhook-secret-rotation-
 * procedure.md). Real JSON-backend store, a real (throwaway) at-rest key
 * pair, no PG required. Confirms the migration tool actually closes the
 * gap documented in server/src/webhooks.js's module header: an envelope
 * sealed under a retired key, opened only via the fallback, ends up
 * re-sealed under the current key alone and no longer needs the fallback.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../../sdk/src/config");
const { Categories, getEventsStore } = require("../../server/src/events-store");
const wh = require("../../server/src/webhooks");
const { resealAll } = require("../reseal-webhook-secrets");

const OLD_KEY = "aa".repeat(32);
const NEW_KEY = "bb".repeat(32);

function mkConfig() {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-reseal-"));
  return loadConfig({ dataRoot });
}

/* Hand-seals a secret under an ARBITRARY key hex, bypassing
 * webhooks.js sealSecret() (which only ever uses the CURRENT env var) —
 * exactly what "sealed under a since-retired key" looks like on disk. */
function sealUnder(keyHex, secret) {
  const key = Buffer.from(keyHex, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return { v: "aes256gcm/v1", iv: iv.toString("hex"), ct: ct.toString("hex"), tag: cipher.getAuthTag().toString("hex") };
}

async function seedEndpoint(config, { endpointId, secretEnvelope, previousSecretEnvelope = null, status = "ACTIVE" }) {
  const store = getEventsStore(config);
  const endpoint = {
    schema: wh.ENDPOINT_SCHEMA,
    endpointId,
    networkId: config.networkId,
    creatorXOnly: "aa".repeat(32),
    url: "https://example.com/hook",
    eventTypes: ["*"],
    label: "",
    status,
    secret: secretEnvelope,
    secretPrefix: "pvwh_deadbeef",
    previousSecret: previousSecretEnvelope,
    previousSecretValidUntilMs: previousSecretEnvelope ? Date.now() + 1000 * 3600 : null,
    secretRotatedAt: null,
    initialCursor: "0",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    revokedAt: status === "REVOKED" ? new Date().toISOString() : null
  };
  await store.write(Categories.WEBHOOK_ENDPOINT, endpointId, endpoint);
  return endpoint;
}

test("reseal-webhook-secrets: dry run reports without writing; --apply re-seals under the current key", async () => {
  const config = mkConfig();
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = OLD_KEY;
  const sealedUnderOld = sealUnder(OLD_KEY, "pvwh_" + "11".repeat(32));
  await seedEndpoint(config, { endpointId: crypto.randomUUID(), secretEnvelope: sealedUnderOld });

  // Rotate: current key is now NEW, previous (fallback) is OLD.
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = NEW_KEY;
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS = OLD_KEY;
  try {
    const dry = await resealAll({ config, apply: false });
    assert.equal(dry.totalEndpoints, 1);
    assert.equal(dry.aes256gcmSecrets, 1);
    assert.equal(dry.resealed, 1);
    assert.deepEqual(dry.failed, []);

    // Dry run must not have written anything: the stored envelope should
    // still only open via the fallback, not the current key alone.
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
    const store = getEventsStore(config);
    const all = await store.listValues(Categories.WEBHOOK_ENDPOINT);
    assert.throws(() => wh.openSecret(all[0].secret), (e) => e.code === "WEBHOOK_SECRET_UNAVAILABLE", "still sealed under the OLD key only — dry run wrote nothing");
    process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS = OLD_KEY;

    const applied = await resealAll({ config, apply: true });
    assert.equal(applied.resealed, 1);

    // After --apply, the envelope must open under the CURRENT key alone —
    // no fallback needed any more.
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
    const after = await store.listValues(Categories.WEBHOOK_ENDPOINT);
    assert.equal(wh.openSecret(after[0].secret), "pvwh_" + "11".repeat(32));
  } finally {
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
  }
});

test("reseal-webhook-secrets: re-seals a live previousSecret too (per-endpoint rotation grace field)", async () => {
  const config = mkConfig();
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = OLD_KEY;
  const currentUnderOld = sealUnder(OLD_KEY, "pvwh_" + "22".repeat(32));
  const previousUnderOld = sealUnder(OLD_KEY, "pvwh_" + "33".repeat(32));
  await seedEndpoint(config, { endpointId: crypto.randomUUID(), secretEnvelope: currentUnderOld, previousSecretEnvelope: previousUnderOld });

  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = NEW_KEY;
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS = OLD_KEY;
  try {
    const applied = await resealAll({ config, apply: true });
    assert.equal(applied.resealed, 1);

    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
    const store = getEventsStore(config);
    const [row] = await store.listValues(Categories.WEBHOOK_ENDPOINT);
    assert.equal(wh.openSecret(row.secret), "pvwh_" + "22".repeat(32));
    assert.equal(wh.openSecret(row.previousSecret), "pvwh_" + "33".repeat(32));
  } finally {
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
  }
});

test("reseal-webhook-secrets: revoked endpoints are migrated too; plain/v1 endpoints are left alone; an unresealable envelope is reported, not thrown", async () => {
  const config = mkConfig();
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = OLD_KEY;
  const revokedSealed = sealUnder(OLD_KEY, "pvwh_" + "44".repeat(32));
  const revokedId = crypto.randomUUID();
  await seedEndpoint(config, { endpointId: revokedId, secretEnvelope: revokedSealed, status: "REVOKED" });

  const plainId = crypto.randomUUID();
  delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY; // plain/v1 mode
  await seedEndpoint(config, { endpointId: plainId, secretEnvelope: { v: "plain/v1", secret: "pvwh_" + "55".repeat(32)} });

  // A THIRD key that was never the current or previous key — this
  // endpoint's secret cannot be opened by either configured key.
  const unrecoverableId = crypto.randomUUID();
  const strandedKey = "cc".repeat(32);
  const sealedUnderStranded = sealUnder(strandedKey, "pvwh_" + "66".repeat(32));
  await seedEndpoint(config, { endpointId: unrecoverableId, secretEnvelope: sealedUnderStranded });

  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = NEW_KEY;
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS = OLD_KEY;
  try {
    const applied = await resealAll({ config, apply: true });
    assert.equal(applied.totalEndpoints, 3);
    assert.equal(applied.plainSecrets, 1);
    assert.equal(applied.aes256gcmSecrets, 2);
    assert.equal(applied.resealed, 1, "only the revoked (recoverable) endpoint was resealed");
    assert.equal(applied.failed.length, 1);
    assert.equal(applied.failed[0].endpointId, unrecoverableId);

    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
    const store = getEventsStore(config);
    const all = await store.listValues(Categories.WEBHOOK_ENDPOINT);
    const revoked = all.find((e) => e.endpointId === revokedId);
    assert.equal(wh.openSecret(revoked.secret), "pvwh_" + "44".repeat(32), "revoked endpoints are migrated too");
  } finally {
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS;
  }
});
