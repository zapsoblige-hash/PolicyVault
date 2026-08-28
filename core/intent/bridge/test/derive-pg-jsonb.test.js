"use strict";

/*
 * BRIDGE — LIVE-PostgreSQL jsonb round-trip regression (G-2 class).
 *
 * The G-2 production incident: PostgreSQL's `jsonb` type canonicalizes
 * object key order (keys are stored sorted by length, then bytewise), so a
 * commitment preimage that depends on insertion order recomputes
 * DIFFERENTLY after a postgres round trip with every value byte-intact.
 * The offline suites simulate that reordering structurally; THIS test is
 * the real-representation proof: a bridge-derived manifest is written into
 * a genuine `jsonb` column, read back through the pg driver, and
 *
 *   (a) the read-back representation is PROVABLY different (jsonb really
 *       reordered keys) while the recomputed manifest hash is IDENTICAL
 *       and the read-back manifest still verifies VERIFIED_EXACT;
 *   (b) a semantically mutated read-back FAILS verification — both an
 *       in-database jsonb_set mutation (stale hash ->
 *       MANIFEST_HASH_MISMATCH) and a rehashsed mutation (the detector
 *       catalogue fires: HIDDEN_RECIPIENT/REQUEST_MISMATCH).
 *
 * Cluster etiquette (embedded dev cluster ~/.policyvault-pg): this test
 * creates its OWN scratch database `pv_jsonb_probe_<random>`, does all
 * work there, and DROPs it in a finally block. It never touches other
 * databases and never starts/stops the cluster. Connection comes from env
 * (PV_JSONB_PROBE_PG_PORT / PV_JSONB_PROBE_PG_USER /
 * PV_JSONB_PROBE_PG_DATABASE, defaulting to 5432 / pvdev / postgres — the
 * default database is only the ADMIN endpoint used to create/drop the
 * scratch database). When the cluster (or the pg driver) is unavailable
 * the test SKIPS with a clear message so the suite stays runnable offline.
 *
 * The pg driver is required READ-ONLY from sdk/node_modules (worktree
 * first, then the primary checkout — sdk/ is byte-identical between them);
 * nothing is installed.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { deriveManifestFromV4Build } = require("../derive");
const { computeManifestHashV1, canonicalJsonStringify } = require("../../canonical");
const { verifyIntentManifest, VERDICTS } = require("../../verify");
const { HEX, spendBuild, ownerTopUpBuild } = require("../testutil/builds");

const PG_PORT = Number(process.env.PV_JSONB_PROBE_PG_PORT ?? "5432");
const PG_USER = process.env.PV_JSONB_PROBE_PG_USER ?? "pvdev";
const PG_ADMIN_DB = process.env.PV_JSONB_PROBE_PG_DATABASE ?? "postgres";

/* Resolve the pg driver read-only: worktree sdk/node_modules first, then
 * the primary checkout (sdk/ is byte-identical; node_modules is not
 * checked in and may be absent from an isolated worktree). */
function resolvePgDriver() {
  const candidates = [
    path.resolve(__dirname, "../../../../sdk/node_modules/pg"),
    path.join(os.homedir(), "policyvault", "sdk", "node_modules", "pg")
  ];
  for (const p of candidates) {
    if (fs.existsSync(path.join(p, "package.json"))) return require(p);
  }
  return null;
}

const clone = (v) => JSON.parse(JSON.stringify(v));
function rehash(m) {
  const body = { ...m };
  delete body.manifestHash;
  return { ...body, manifestHash: computeManifestHashV1(body) };
}

test("G-2 LIVE: bridge-derived manifest survives a REAL PostgreSQL jsonb round trip (and mutations fail verification)", async (t) => {
  const pg = resolvePgDriver();
  if (pg === null) {
    t.skip("pg driver not found in sdk/node_modules (worktree or primary checkout) — live jsonb regression skipped");
    return;
  }

  const admin = new pg.Client({ host: "127.0.0.1", port: PG_PORT, user: PG_USER, database: PG_ADMIN_DB, connectionTimeoutMillis: 3000 });
  try {
    await admin.connect();
  } catch (e) {
    t.skip(`embedded PostgreSQL cluster not reachable on 127.0.0.1:${PG_PORT} (${e.code ?? e.message}) — live jsonb regression skipped (offline run)`);
    return;
  }

  const scratchDb = `pv_jsonb_probe_${crypto.randomBytes(6).toString("hex")}`;
  assert.match(scratchDb, /^pv_jsonb_probe_[0-9a-f]{12}$/, "scratch database name is a safe identifier");
  let probe = null;
  try {
    await admin.query(`CREATE DATABASE ${scratchDb}`);
    t.diagnostic(`EXECUTED against live PostgreSQL on port ${PG_PORT}; scratch database ${scratchDb}`);

    probe = new pg.Client({ host: "127.0.0.1", port: PG_PORT, user: PG_USER, database: scratchDb, connectionTimeoutMillis: 3000 });
    await probe.connect();
    await probe.query("CREATE TABLE pv_manifests (id text PRIMARY KEY, doc jsonb NOT NULL)");

    for (const [name, build] of [["agentSpend", spendBuild()], ["ownerTopUp", ownerTopUpBuild()]]) {
      const manifest = deriveManifestFromV4Build({ build });

      /* store with the manifest's NATURAL insertion key order */
      await probe.query("INSERT INTO pv_manifests (id, doc) VALUES ($1, $2::jsonb)", [name, JSON.stringify(manifest)]);
      const readBack = (await probe.query("SELECT doc FROM pv_manifests WHERE id = $1", [name])).rows[0].doc;

      /* jsonb GENUINELY reordered keys: the representation changed... */
      assert.notEqual(JSON.stringify(readBack), JSON.stringify(manifest), `${name}: jsonb must actually reorder keys for this regression to bite`);
      /* ...but the canonical serialization — and therefore the hash — did not. */
      assert.equal(canonicalJsonStringify(readBack), canonicalJsonStringify(manifest), `${name}: canonical serialization drift after jsonb round trip`);
      const body = { ...readBack };
      delete body.manifestHash;
      assert.equal(computeManifestHashV1(body), manifest.manifestHash, `${name}: (a) recomputed hash over the READ-BACK jsonb value differs from the original — G-2 regression`);

      /* the read-back manifest still fully verifies */
      const verified = verifyIntentManifest({ manifest: readBack });
      assert.equal(verified.verdict, VERDICTS.VERIFIED_EXACT, `${name}: read-back manifest must verify: ${JSON.stringify(verified.failures)}`);
      assert.equal(verified.manifestHash, manifest.manifestHash, name);
    }

    /* (b) semantic mutation IN THE DATABASE: redirect the declared payment
     * recipient via jsonb_set. The stored hash is now stale — verification
     * of the read-back document must refuse with MANIFEST_HASH_MISMATCH. */
    const attacker = HEX("99");
    await probe.query("UPDATE pv_manifests SET doc = jsonb_set(doc, '{payment,recipientXOnly}', to_jsonb($1::text)) WHERE id = $2", [attacker, "agentSpend"]);
    const mutated = (await probe.query("SELECT doc FROM pv_manifests WHERE id = $1", ["agentSpend"])).rows[0].doc;
    assert.equal(mutated.payment.recipientXOnly, attacker, "the in-database mutation must have landed");
    const staleHash = verifyIntentManifest({ manifest: mutated });
    assert.equal(staleHash.verdict, VERDICTS.REFUSED, "(b) a semantically mutated read-back must fail verification");
    assert.ok(staleHash.failures.some((f) => f.code === "MANIFEST_HASH_MISMATCH"), JSON.stringify(staleHash.failures));

    /* (b') stronger variant: the mutating party also recomputes the hash —
     * the detector catalogue itself must refuse the dishonest document. */
    const rehashsed = rehash(clone(mutated));
    const detectors = verifyIntentManifest({ manifest: rehashsed });
    assert.equal(detectors.verdict, VERDICTS.REFUSED, "a rehashsed mutated manifest must still refuse");
    assert.ok(
      detectors.failures.some((f) => f.code === "HIDDEN_RECIPIENT" || f.code === "REQUEST_MISMATCH"),
      JSON.stringify(detectors.failures)
    );

    t.diagnostic("jsonb round-trip hash stability + mutation refusal PROVEN on live PostgreSQL");
  } finally {
    if (probe !== null) {
      try {
        await probe.end();
      } catch {
        /* closing best-effort — the drop below is the real cleanup */
      }
    }
    try {
      await admin.query(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
    } finally {
      await admin.end();
    }
  }
});
