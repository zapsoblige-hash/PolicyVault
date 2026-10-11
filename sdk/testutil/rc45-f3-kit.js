"use strict";
/*
 * RC45 F3 test kit (fix item F3 RC45-L5-OWNER-BREAKGLASS; plan
 * rc45-simplified-plan-r2 §2.3 touch points, §5 A1/A2/A4, §8 rules and T3/T8).
 * Internal RED-first regression material for the RC45 candidate; not an audit.
 *
 * Used by sdk/test/rc45-t3-owner-breakglass.test.js. It adds, on top of the F5
 * kit (sdk/testutil/rc45-f5-kit.js, reused unchanged for vaults, wallets, the
 * explicit chain model, snapshots and install):
 *
 *   - buildApart: the delegate noise of the T3 base (32 BUILT agent spends and
 *     300 agent spends built then rejected) is built by the CANDIDATE builder in
 *     parallel child processes, each against its own scratch copy of the
 *     template (a real build costs about 3 s; 332 sequential builds would not
 *     fit the per-file watchdog), and merged back: each built request record
 *     and, for a request still BUILT, its budget reservation. Builds write no
 *     audit row; any row a child appended is merged too. CANDIDATE-WRITTEN,
 *     built apart and merged: the merged set is what the same builder writes
 *     sequentially (every record is independent, the merged ACTIVE
 *     reservations total 32 KAS < the 50 KAS period budget, so every admission
 *     a sequential run would evaluate also passes).
 *   - apiFor: the real hosted route handler (server/src/api.js handle) with a
 *     signed-in wallet session (TEST keys only), returning {status, code, body}
 *     for both answers and refusals.
 *   - submitThroughModel: route-level submit legs cannot pass `rpc`
 *     (server/src/api.js calls submitWalletRequestV4({ config, requestId })),
 *     and the default rpcUrl is the operator's testnet-10 node; so, as plan §8
 *     rules allow for route-level Verify (CR-M14, CR2-L12), the module-cache
 *     export is wrapped to call the REAL submitWalletRequestV4 with the
 *     explicit chain model's rpc (never a stub), and restored afterwards.
 *   - events: the durable platform event stream (request.confirmed, ...).
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node
 * observation comes from the explicit chain model passed as `rpc`.
 */
const path = require("node:path"), cp = require("node:child_process");
const assert = require("node:assert/strict");
const K = require("./rc45-f5-kit");

const CHILD_MODE = "rc45-f3-build-child", CHILD_TAG = "RC45-F3-BUILD-CHILD-RESULT ";
const SDK_SRC = path.join(__dirname, "..", "src");

/* ---------------- parallel candidate builds, merged ---------------- */
function runBuildChild(input) {
  return new Promise((resolve, reject) => {
    const child = cp.spawn(process.execPath, [__filename, CHILD_MODE, JSON.stringify(input)], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env } });
    let out = "", err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      const line = out.split("\n").find((l) => l.startsWith(CHILD_TAG));
      if (code !== 0 || signal || !line) return reject(new Error(`RC45 F3 build child failed (code ${code}, signal ${signal}): ${err.slice(-4000)}`));
      resolve(JSON.parse(line.slice(CHILD_TAG.length)));
    });
  });
}
/*
 * Build `jobs` ({ sompi, recipient: x-only hex, reject: boolean }) as agent spends on vault `v` in `children` parallel
 * child processes (candidate builder, TEST agent key), each in a scratch copy of `template`, then merge every built
 * request record (and the reservation of each request still BUILT) plus any new audit row into `template`.
 * Returns [{ requestId, txId, reject }] in job order.
 */
async function buildApart(m, template, v, jobs, { children = 24, track = () => {} } = {}) {
  const C = m.store.Categories, s = m.store.getStore(template), base = await K.snapshot(m, template);
  const seen = new Set(base.audit.map((row) => JSON.stringify(row)));
  const per = Math.max(1, Math.ceil(jobs.length / children)), slices = [];
  for (let i = 0; i < jobs.length; i += per) slices.push(jobs.slice(i, i + per));
  const runs = await Promise.all(slices.map(async (slice) => {
    const root = K.ownedTempRoot("pv-rc45-f3-apart-"); track(root);
    const scratch = m.config.loadConfig({ dataRoot: root, rpcUrl: K.LOOPBACK });
    await K.install(m, scratch, base);
    K.warmCompileCache(template.dataRoot, root);
    const built = await runBuildChild({ dataRoot: root, vaultId: v.vaultId, jobs: slice });
    assert.equal(built.length, slice.length, "every job of the slice was built");
    return { scratch, built };
  }));
  const out = [];
  for (const { scratch, built } of runs) {
    const ss = m.store.getStore(scratch);
    for (const b of built) {
      const record = await ss.read(C.REQUEST, b.requestId);
      assert.ok(record, `the child persisted ${b.requestId}`);
      assert.equal(record.state, b.reject ? "WALLET_REJECTED" : "BUILT");
      await s.write(C.REQUEST, b.requestId, record);
      const key = m.budget.reservationKey(record), reservation = await ss.read(C.TRANSITION_CLAIM, key);
      if (b.reject) assert.equal(reservation, null, "a rejected build released its reservation");
      else { assert.ok(reservation, "a BUILT agent spend holds its reservation"); await s.write(C.TRANSITION_CLAIM, key, reservation); }
      out.push(b);
    }
    for (const row of [...(await ss.readAudit({ limit: 5000 }))].reverse()) { const j = JSON.stringify(row); if (!seen.has(j)) { seen.add(j); await s.appendAudit(row); } }
  }
  return out;
}
async function buildChild(input) {
  const m = K.modulesOf(SDK_SRC);
  const config = m.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: K.LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const w = K.walletsFor(config), k = K.kitFor(m, config, w), v = { vaultId: input.vaultId }, out = [];
  for (const job of input.jobs) {
    const r = await k.agentSpendSompi(v, BigInt(job.sompi), { xonly: job.recipient });
    assert.equal(r.state, "BUILT");
    if (job.reject) assert.equal((await m.wr4.markWalletRejected(config, r.requestId)).state, "WALLET_REJECTED");
    out.push({ requestId: r.requestId, txId: r.txId, reject: job.reject === true });
    await K.sleep(2); // distinct createdAt values
  }
  return out;
}

/* ---------------- the hosted route handler ---------------- */
function apiFor(config) {
  const { handle } = require("../../server/src/api");
  const kaspa = require(config.rustyKaspaModule);
  async function call(method, segments, body = null, cookie = null, query = {}) {
    try {
      const r = await handle(config, method, segments, query, body, cookie ? { headers: { cookie } } : {});
      return { status: r.status, code: null, body: r.body, headers: r.headers ?? {}, message: null };
    } catch (e) {
      if (e && e.code === "ERR_ASSERTION") throw e;
      return { status: e && e.status !== undefined ? e.status : null, code: e && e.code ? e.code : null, body: null, headers: {}, message: String(e && e.message), extra: e && e.extra };
    }
  }
  async function signIn(wallet) {
    const priv = new kaspa.PrivateKey(wallet.secretHex);
    const ch = await call("POST", ["auth", "challenge"], { walletAddress: wallet.address });
    assert.equal(ch.status, 200, `auth challenge (${ch.code} ${ch.message})`);
    const signature = kaspa.signMessage({ message: ch.body.challenge.message, privateKey: priv.toString() });
    const v = await call("POST", ["auth", "verify"], { nonce: ch.body.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() });
    assert.equal(v.status, 200, `auth verify (${v.code} ${v.message})`);
    return String(v.headers["Set-Cookie"]).split(";")[0];
  }
  return {
    call, signIn,
    build: (cookie, body) => call("POST", ["wallet", "v4", "requests"], body, cookie),
    signature: (cookie, requestId, signedSafeJson) => call("POST", ["wallet", "v4", "requests", requestId, "signature"], { signedSafeJson }, cookie),
    submit: (cookie, requestId) => call("POST", ["wallet", "v4", "requests", requestId, "submit"], {}, cookie),
    reject: (cookie, requestId) => call("POST", ["wallet", "v4", "requests", requestId, "reject"], {}, cookie)
  };
}

/* Route-level submit through the explicit chain model: wrap the REAL export, call `fn`, restore. */
async function submitThroughModel(getModel, fn) {
  const mod = require(path.join(SDK_SRC, "wallet-submit-v4.js"));
  const real = mod.submitWalletRequestV4;
  mod.submitWalletRequestV4 = (args) => real({ ...args, rpc: getModel().rpc, pollAttempts: 1, pollDelayMs: 0 });
  try { return await fn(); } finally { mod.submitWalletRequestV4 = real; }
}

/* The durable platform events of `type` correlated to `requestId`. */
async function eventsOf(config, type, requestId) {
  const { getEventsStore } = require("../../server/src/events-store");
  const rows = await getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500 });
  return rows.map((r) => r.event).filter((e) => e.type === type && (!requestId || (e.correlation && e.correlation.requestId === requestId)));
}

if (require.main === module && process.argv[2] === CHILD_MODE) {
  buildChild(JSON.parse(process.argv[3])).then(
    (result) => { process.stdout.write(`${CHILD_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = { buildApart, apiFor, submitThroughModel, eventsOf };
