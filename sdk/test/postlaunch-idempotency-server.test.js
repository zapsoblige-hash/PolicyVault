"use strict";

/*
 * IDEMPOTENT MACHINE OPERATIONS (completion-standard surface 14;
 * docs/postlaunch/platform-agent-api-spec.md; server/src/idempotency.js).
 *
 * Two layers of proof:
 *   - direct unit tests of withIdempotency (fast, precise control over the
 *     durable-vs-transient outcome split and staleness reclaim, which are
 *     awkward to induce through a real route);
 *   - real server.api.handle() end-to-end through a genuine mutating v0.4
 *     build route (the FUNDS-SAFETY-CRITICAL property): two concurrent
 *     identical POSTs sharing an Idempotency-Key produce exactly ONE
 *     durable wallet-request, never two.
 * JSON backend (no PostgreSQL needed for these properties — see
 * server/src/idempotency.js; PG-specific correctness is proven separately
 * in postlaunch-platform-store-pg.test.js).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { withIdempotency } = require("../../server/src/idempotency");
const { Categories, getPlatformStore } = require("../../server/src/platform-store");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-idem-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0xe1);
const AGENT = KEY(0xe2);
const RECIP = KEY(0xe3);
const VAULT_ID = "5b".repeat(32);

const POST = (segs, body, headers) => handle(config, "POST", segs, {}, body, { headers: headers ?? {} });
const requestFiles = () => (fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")) : []);

async function seedVault() {
  const template = { owner: XO(A), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "idempotency test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "5c".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "5d".repeat(32) },
    creationTxId: "5e".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const spendBody = (amountKas, extra = {}) => ({
  vaultId: VAULT_ID,
  action: "agentSpend",
  params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) },
  signerAddress: ADDR(AGENT),
  ...extra
});

test("setup: seed a real v0.4 vault", async () => {
  await seedVault();
});

/* ---- direct unit tests of withIdempotency (precise, fast) ---- */

test("unit: fresh claim executes exactly once; identical replay returns the SAME response and never re-invokes run()", async () => {
  let calls = 0;
  const run = async () => {
    calls += 1;
    return { status: 201, body: { created: true, n: calls } };
  };
  const args = { rawKey: "unit-key-1", principal: { xOnlyPubkey: "aa".repeat(32) }, method: "POST", segments: ["x"], query: {}, body: { a: 1 } };
  const r1 = await withIdempotency(config, args, run);
  assert.equal(r1.status, 201);
  assert.equal(r1.body.n, 1);
  assert.equal(r1.body.idempotency.replayed, false);

  const r2 = await withIdempotency(config, args, run);
  assert.equal(calls, 1, "run() must not execute a second time on replay");
  assert.equal(r2.body.n, 1, "the replayed body is the ORIGINAL response, not a fresh one");
  assert.equal(r2.body.idempotency.replayed, true);
  assert.equal(r2.body.idempotency.key, "unit-key-1");
});

test("unit: the SAME key with a DIFFERENT body is a deterministic conflict — run() is never called", async () => {
  let calls = 0;
  const run = async () => {
    calls += 1;
    return { status: 201, body: {} };
  };
  const base = { rawKey: "unit-key-2", principal: { xOnlyPubkey: "bb".repeat(32) }, method: "POST", segments: ["x"], query: {} };
  await withIdempotency(config, { ...base, body: { a: 1 } }, run);
  assert.equal(calls, 1);
  await assert.rejects(
    () => withIdempotency(config, { ...base, body: { a: 2 } }, run),
    (e) => e.status === 409 && e.code === "IDEMPOTENCY_KEY_CONFLICT"
  );
  assert.equal(calls, 1, "a conflicting-body reuse must never touch run()");
});

test("unit: a durable business refusal (<500) is recorded and replayed verbatim on retry", async () => {
  const run = async () => {
    const e = new Error("policy says no");
    e.status = 422;
    e.code = "SOME_REFUSAL";
    e.extra = { detail: "x" };
    throw e;
  };
  const args = { rawKey: "unit-key-3", principal: { xOnlyPubkey: "cc".repeat(32) }, method: "POST", segments: ["x"], query: {}, body: {} };
  await assert.rejects(() => withIdempotency(config, args, run), (e) => e.status === 422 && e.code === "SOME_REFUSAL" && e.extra.idempotency.replayed === false);
  await assert.rejects(() => withIdempotency(config, args, run), (e) => e.status === 422 && e.code === "SOME_REFUSAL" && e.extra.idempotency.replayed === true);
});

test("unit: a transient failure (>=500 or no status) RELEASES the claim — the key is retryable, not poisoned", async () => {
  let calls = 0;
  const run = async () => {
    calls += 1;
    if (calls === 1) {
      const e = new Error("kaspad is unreachable");
      e.status = 503;
      throw e;
    }
    return { status: 200, body: { ok: true, attempt: calls } };
  };
  const args = { rawKey: "unit-key-4", principal: { xOnlyPubkey: "dd".repeat(32) }, method: "POST", segments: ["x"], query: {}, body: {} };
  await assert.rejects(() => withIdempotency(config, args, run), (e) => e.status === 503);
  assert.equal(calls, 1);
  const r = await withIdempotency(config, args, run);
  assert.equal(calls, 2, "a transient failure must allow a real retry, not a replay of nothing");
  assert.equal(r.body.attempt, 2);
  assert.equal(r.body.idempotency.replayed, false, "this is a FRESH execution, not a replay");
});

test("unit: two DIFFERENT principals using the identical raw key never collide", async () => {
  let calls = 0;
  const run = async () => {
    calls += 1;
    return { status: 200, body: { n: calls } };
  };
  const bodyArgs = { rawKey: "shared-raw-key", method: "POST", segments: ["x"], query: {}, body: {} };
  const r1 = await withIdempotency(config, { ...bodyArgs, principal: { xOnlyPubkey: "ee".repeat(32) } }, run);
  const r2 = await withIdempotency(config, { ...bodyArgs, principal: { xOnlyPubkey: "ff".repeat(32) } }, run);
  assert.equal(calls, 2, "different principals must get independent executions for the same raw key");
  assert.notEqual(r1.body.n, r2.body.n);

  // a null principal (self-hosted/anonymous) is its OWN shared scope —
  // proven distinct from either identity above.
  const r3 = await withIdempotency(config, { ...bodyArgs, principal: null }, run);
  assert.equal(calls, 3);
});

test("unit: a STALE (crashed) IN_PROGRESS claim is reclaimed after the staleness window, not held forever", async () => {
  const store = getPlatformStore(config);
  const compositeKey = "wallet:" + "11".repeat(32) + ":stale-key";
  await store.write(Categories.IDEMPOTENCY, compositeKey, {
    schema: require("../../server/src/idempotency").SCHEMA,
    status: "IN_PROGRESS",
    requestFingerprint: require("../../core/intent").sha256Hex(require("../../core/intent").canonicalJsonStringify({ method: "POST", path: ["x"], query: {}, body: { a: 1 } })),
    response: null,
    createdAtMs: Date.now() - 10 * 60 * 1000, // 10 minutes ago — well past IN_PROGRESS_STALE_MS
    completedAtMs: null
  });
  let calls = 0;
  const run = async () => {
    calls += 1;
    return { status: 200, body: { reclaimed: true } };
  };
  const r = await withIdempotency(
    config,
    { rawKey: "stale-key", principal: { xOnlyPubkey: "11".repeat(32) }, method: "POST", segments: ["x"], query: {}, body: { a: 1 } },
    run
  );
  assert.equal(calls, 1, "a stale IN_PROGRESS claim must be reclaimable, not stuck forever");
  assert.equal(r.body.reclaimed, true);
});

test("unit: Idempotency-Key shape is validated (bounded length, restricted charset) — fails closed", async () => {
  await assert.rejects(
    () => withIdempotency(config, { rawKey: "", principal: null, method: "POST", segments: ["x"], query: {}, body: {} }, async () => ({ status: 200, body: {} })),
    (e) => e.status === 400 && e.code === "IDEMPOTENCY_KEY_INVALID"
  );
  await assert.rejects(
    () => withIdempotency(config, { rawKey: "x".repeat(300), principal: null, method: "POST", segments: ["x"], query: {}, body: {} }, async () => ({ status: 200, body: {} })),
    (e) => e.status === 400 && e.code === "IDEMPOTENCY_KEY_INVALID"
  );
  await assert.rejects(
    () => withIdempotency(config, { rawKey: "has a space", principal: null, method: "POST", segments: ["x"], query: {}, body: {} }, async () => ({ status: 200, body: {} })),
    (e) => e.status === 400 && e.code === "IDEMPOTENCY_KEY_INVALID"
  );
});

/* ---- real end-to-end proof through the real server + real build ---- */

test("end-to-end: header-absent behavior is byte-identical to before (no idempotency field appears)", async () => {
  const r = await POST(["wallet", "v4", "requests"], spendBody(1n), {});
  assert.equal(r.status, 201);
  assert.equal(r.body.idempotency, undefined);
});

test("end-to-end FUNDS-SAFETY PROOF: two concurrent identical POSTs with the same Idempotency-Key create exactly ONE durable wallet-request", async () => {
  const before = requestFiles().length;
  const headers = { authorization: undefined, cookie: undefined, idempotencyKey: "spend-once-key-1" };
  const body = spendBody(3n);
  // allSettled — NOT Promise.all: both calls must be fully awaited to
  // completion before this test returns (Promise.all would propagate the
  // loser's rejection immediately and leave the winner's build running
  // ORPHANED in the background, unawaited, racing into later tests).
  const [s1, s2] = await Promise.allSettled([POST(["wallet", "v4", "requests"], body, headers), POST(["wallet", "v4", "requests"], body, headers)]);
  const results = [s1, s2].map((s) => (s.status === "fulfilled" ? { ok: true, status: s.value.status, body: s.value.body } : { ok: false, status: s.reason.status, code: s.reason.code }));

  const statuses = results.map((r) => r.status).sort();
  // Exactly one call reaches the real builder; the other is either a
  // clean 409 (still in progress) or a 201 replay of the SAME requestId —
  // either way, never two DISTINCT durable requests.
  assert.ok(statuses[0] === 201 || statuses[0] === 409, JSON.stringify(results));
  for (const r of results) if (!r.ok) assert.equal(r.code, "IDEMPOTENCY_IN_PROGRESS", JSON.stringify(results));
  const after = requestFiles().length;
  assert.equal(after, before + 1, "exactly one durable wallet-request must exist after both calls settle — never two");

  const successResponses = results.filter((r) => r.status === 201);
  if (successResponses.length === 2) {
    assert.equal(successResponses[0].body.request.requestId, successResponses[1].body.request.requestId, "both 201s must be the SAME request, not two distinct builds");
  }
});

test("end-to-end: replaying the SAME key + SAME body returns the original request (idempotent replay marker), and STILL creates no second durable request", async () => {
  const before = requestFiles().length;
  const headers = { idempotencyKey: "spend-once-key-2" };
  const body = spendBody(1n);
  const first = await POST(["wallet", "v4", "requests"], body, headers);
  assert.equal(first.status, 201);
  const afterFirst = requestFiles().length;

  const replay = await POST(["wallet", "v4", "requests"], body, headers);
  assert.equal(replay.status, 201);
  assert.equal(replay.body.idempotency.replayed, true);
  assert.equal(replay.body.request.requestId, first.body.request.requestId);
  assert.equal(requestFiles().length, afterFirst, "a replay must create no additional durable request");
  assert.equal(afterFirst, before + 1);
});

test("end-to-end: the SAME key with a DIFFERENT body deterministically conflicts (409) and builds nothing", async () => {
  const before = requestFiles().length;
  const headers = { idempotencyKey: "spend-once-key-3" };
  await POST(["wallet", "v4", "requests"], spendBody(1n), headers);
  const afterFirst = requestFiles().length;

  const e = await (async () => {
    try {
      await POST(["wallet", "v4", "requests"], spendBody(2n), headers);
      assert.fail("expected a conflict");
    } catch (err) {
      return err;
    }
  })();
  assert.equal(e.status, 409);
  assert.equal(e.code, "IDEMPOTENCY_KEY_CONFLICT");
  assert.equal(requestFiles().length, afterFirst, "a conflicting reuse must build nothing");
  assert.equal(afterFirst, before + 1);
});

test("end-to-end: idempotency keys are scoped per identity — the SAME raw key from a DIFFERENT machine identity is an independent, fully executed request", async () => {
  const chA = await POST(["auth", "challenge"], { walletAddress: ADDR(A) });
  const sigA = kaspa.signMessage({ message: chA.body.challenge.message, privateKey: A.toString() });
  const vA = await POST(["auth", "verify"], { nonce: chA.body.challenge.nonce, signature: sigA, publicKey: A.toPublicKey().toString().toLowerCase() });
  const cookieA = vA.headers["Set-Cookie"].split(";")[0];

  const id1 = await POST(["identities"], { scopes: ["request:build"] }, { cookie: cookieA });
  const id2 = await POST(["identities"], { scopes: ["request:build"] }, { cookie: cookieA });

  const before = requestFiles().length;
  const key = "shared-across-identities";
  const r1 = await POST(["wallet", "v4", "requests"], spendBody(1n), { authorization: `Bearer ${id1.body.credential.token}`, idempotencyKey: key });
  const r2 = await POST(["wallet", "v4", "requests"], spendBody(1n), { authorization: `Bearer ${id2.body.credential.token}`, idempotencyKey: key });
  assert.equal(r1.status, 201);
  assert.equal(r2.status, 201);
  assert.notEqual(r1.body.request.requestId, r2.body.request.requestId, "different identities must never share an idempotency scope");
  assert.equal(requestFiles().length, before + 2);
});
