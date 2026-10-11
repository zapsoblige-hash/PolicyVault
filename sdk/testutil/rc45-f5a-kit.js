"use strict";
/*
 * RC45 F5a test kit (plan amendment PA-01 revision 1, rule 1 / review R1, on
 * plan rc45-simplified-plan-r2 §2.2 step 8 and §2.5(1)). Internal RED-first
 * regression material for the RC45 candidate; not an audit.
 *
 * Used by sdk/test/rc45-t5-adoption.test.js for the one leg whose base the
 * product cannot produce: the v0.4 manifest loader canonicalizes
 * live.covenantId (normalizeHex: 32-byte lowercase hex) and lastRecordedLive
 * accepts only a HEX64 covenant id, so a base WITHOUT a valid covenant id
 * reaches step 8 only through a seam (defence in depth for rule 1: with no
 * canonical base.covenantId step 8 has no candidates, so a null expected id
 * can never match a covenant-less output).
 *
 * The Verify child (this file run as a script) runs the candidate
 * reconcileVaultV4(config, vaultId, { rpc }) in a FRESH process against the
 * same JSON root or PostgreSQL database, with a serialized chain model of
 * sdk/testutil/rc45-f5-kit.js. Before any candidate module binds it, the real
 * loadManifestV4 is wrapped: for the named vault it returns the real loaded
 * manifest with live.covenantId replaced (SYNTHETIC). Everything else is the
 * real candidate: the pass, the store, the compiler. The child reports how
 * many loads the seam rewrote, so a seam that no longer reaches the pass fails
 * the leg instead of passing it vacuously.
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node
 * observation comes from the explicit chain model passed as `rpc`. TEST keys
 * only.
 */
const path = require("node:path"), cp = require("node:child_process");
const assert = require("node:assert/strict");
const K = require("./rc45-f5-kit");

const SDK_SRC = path.join(__dirname, "..", "src");
const CHILD_MODE = "rc45-f5a-verify-child", CHILD_TAG = "RC45-F5A-VERIFY-CHILD-RESULT ";

async function verifyChild(input) {
  // The seam goes in before reconcile-v4 (or any other module that binds loadManifestV4) is loaded.
  const M4 = require(path.join(SDK_SRC, "manifest-v4.js"));
  const load = M4.loadManifestV4;
  let seam = 0;
  M4.loadManifestV4 = async (...args) => {
    const m = await load(...args);
    if (!m || !m.live || m.vaultId !== input.vaultId) return m;
    seam += 1;
    return Object.freeze({ ...m, live: Object.freeze({ ...m.live, covenantId: input.liveCovenantId }) });
  };
  const cand = K.modulesOf(SDK_SRC);
  assert.equal(cand.manifest4, M4, "one manifest-v4 module instance carries the seam");
  let config;
  if (input.pg) {
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: input.pg.host, pgPort: input.pg.port, pgUser: input.pg.user, pgDatabase: input.pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot: input.dataRoot, rpcUrl: K.LOOPBACK });
    await cand.store.openPgStore(config, { migrate: false });
  } else config = cand.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: K.LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const store = cand.store.getStore(config);
  const model = K.chainModel(config, input.model);
  let result;
  try {
    const out = await cand.reconcile4.reconcileVaultV4(config, input.vaultId, { rpc: model.rpc });
    result = { ok: true, value: K.jsonSafe(out), seam, calls: model.calls.length };
  } catch (error) {
    result = { ok: false, code: error.code ?? null, message: String(error.message), seam, calls: model.calls.length };
  }
  if (input.pg) await store.close();
  return result;
}
/* Run the candidate Verify in a fresh child against `x` (a case from a suite's fresh()) with the vault's recorded
 * live.covenantId presented to the pass as `liveCovenantId`. */
function verifyWithLiveCovenantIdInChild(x, v, liveCovenantId, { env = {}, pg = null } = {}) {
  const payload = { vaultId: v.vaultId, liveCovenantId, dataRoot: x.config.dataRoot, pg: x.pgDatabase ? { ...pg, database: x.pgDatabase } : null, model: x.model.serialize() };
  const child = cp.spawnSync(process.execPath, [__filename, CHILD_MODE], { input: JSON.stringify(payload), encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, ...env } });
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(CHILD_TAG));
  return { signal: child.signal, status: child.status, stderr: (child.stderr || "").slice(-4000), result: line ? JSON.parse(line.slice(CHILD_TAG.length)) : null };
}

if (require.main === module && process.argv[2] === CHILD_MODE) {
  const chunks = [];
  process.stdin.on("data", (d) => chunks.push(d));
  process.stdin.on("end", () => {
    verifyChild(JSON.parse(Buffer.concat(chunks).toString("utf8"))).then(
      (result) => { process.stdout.write(`${CHILD_TAG}${JSON.stringify(result)}\n`); },
      (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
    );
  });
}

module.exports = { verifyWithLiveCovenantIdInChild };
