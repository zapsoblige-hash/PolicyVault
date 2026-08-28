"use strict";

/*
 * SDK — pre-build period-budget reservations (full-scale surface 15;
 * sdk/src/budget-reservation.js). UNIT + ADVERSARIAL + CRASH-RECOVERY
 * layers against the JSON backend (the PG parity battery lives in
 * budget-reservation-pg.test.js).
 *
 * Proves, against the REAL build/finalize pipeline (real silverc compile,
 * real encoder, real VM preflight — no reimplementation):
 *   - a v4 agent-spend BUILD takes a durable ACTIVE reservation before
 *     the request is persisted; owner ops and simulate take none;
 *   - two builds that together exceed the period budget: exactly one
 *     durable request, the other refuses BUDGET_RESERVED_EXCEEDED with a
 *     deterministic explanation naming the holder;
 *   - reject releases; finalize CONSUMES (and consumed keeps counting
 *     until the manifest advances); rollover windows are independent;
 *   - crashed/orphaned/context-stale reservations are reclaimed by the
 *     deterministic admission sweep; forged/unknown/corrupt records fail
 *     closed;
 *   - the frozen transaction bytes for a given build are IDENTICAL with
 *     the reservation layer in place (no consensus-visible byte changes).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4, loadManifestV4 } = require("../src/manifest-v4");
const { buildV4Transaction } = require("../src/vault-builders-v4");
const {
  buildWalletRequestV4,
  finalizeWalletRequestV4,
  markWalletRejected,
  loadRequest,
  saveRequest,
  RequestState
} = require("../src/wallet-requests-v4");
const {
  RESERVATION_SCHEMA,
  RESERVATION_LOCK_SCHEMA,
  reservationKey,
  consumeReservationForRequest,
  listReservationsV4
} = require("../src/budget-reservation");
const { getStore, Categories } = require("../src/store");
const { makeDevSigner } = require("../src/signer-dev");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-resv-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const fuelKey = KEY(3);
const recipient = KEY(0x28);
const approvers = [KEY(20), KEY(21)];

const VAULT_ID = "5e".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

/* TIGHT budget: maxPerSpend 20, periodBudget 30 — two max spends overflow. */
function tightEntry(over = {}) {
  return {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (30n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (25n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipient)], ...over
  };
}

function stateFor(registry, over = {}) {
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  return normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0", ...over
  });
}

let seedCounter = 0;
async function seedManifest(registry, over = {}) {
  seedCounter += 1;
  const outTxId = (0xa0 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const state = stateFor(registry, over);
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId,
    vaultId: VAULT_ID, label: "resv-test", status: "ACTIVE", template, agentRegistry: registry,
    live: {
      state: stateToJsonV4(state), stateId,
      outpoint: { transactionId: outTxId, index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256, covenantId: "4d".repeat(32)
    },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const spendParams = (kas, extra = {}) => ({ payAmountSompi: (kas * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), ...extra });
const buildSpend = (kas, extra = {}) =>
  buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(kas, extra), signerAddress: ADDR(agentA) });

function secretOf(kp) {
  const map = { [XO(owner)]: 1, [XO(agentA)]: 0x1e, [XO(fuelKey)]: 3, [XO(recipient)]: 0x28 };
  approvers.forEach((a, i) => (map[XO(a)] = 20 + i));
  const v = map[XO(kp)];
  if (v === undefined) throw new Error("unknown test key");
  return v;
}
function devSign(request, kp) {
  const signer = makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) });
  return signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
}

const listResv = () => listReservationsV4(config, { vaultId: VAULT_ID, agentPk: XO(agentA) });
const store = () => getStore(config);

/* ------------------------------------------------------------------ */
/* UNIT                                                                */
/* ------------------------------------------------------------------ */

test("UNIT: an agent-spend BUILD takes a durable ACTIVE reservation; the request records its key", async () => {
  const manifest = await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  assert.equal(req.state, RequestState.BUILT);
  assert.equal(req.reservationKey, reservationKey({ vaultId: VAULT_ID, agentPk: XO(agentA), requestId: req.requestId }));
  const resv = await listResv();
  assert.equal(resv.length, 1);
  const r = resv[0];
  assert.equal(r.schema, RESERVATION_SCHEMA);
  assert.equal(r.status, "ACTIVE");
  assert.equal(r.requestId, req.requestId);
  assert.equal(r.amountSompi, (20n * KAS).toString());
  assert.equal(r.windowStartDaa, "541000000");
  assert.equal(r.newSpentSompi, (20n * KAS).toString());
  assert.equal(r.periodBudgetSompi, (30n * KAS).toString());
  assert.equal(r.predecessorStateId, manifest.live.stateId);
  assert.deepEqual(r.predecessorOutpoint, manifest.live.outpoint);
  assert.equal(r.txId, null);
  await markWalletRejected(config, req.requestId); // clean slate for the next test
  assert.equal((await listResv()).length, 0, "rejection releases the reservation");
});

test("UNIT: byte identity — the pipeline's frozen tx is IDENTICAL to the raw builder's (no consensus-visible byte changes)", async () => {
  const manifest = await seedManifest([tightEntry()]);
  const req = await buildSpend(7n);
  const entry = manifest.agentRegistry[0];
  const direct = buildV4Transaction({
    config,
    contractVersion: manifest.contractVersion,
    templateInput: { owner: template.owner, vaultId: VAULT_ID },
    stateInput: stateToJsonV4(manifest.live.state),
    action: "agentSpend",
    params: {
      payAmountSompi: (7n * KAS).toString(),
      agentPk: XO(agentA),
      agents: manifest.agentRegistry.map((e) => ({ ...e.policy })),
      recipient: XO(recipient),
      recipients: [...entry.recipients],
      periodsElapsed: "0"
    },
    chain: {
      predecessorOutpoint: manifest.live.outpoint,
      predecessorValue: (manifest.live.state.protectedValue + manifest.live.state.feeReserve).toString(),
      covenantId: manifest.live.covenantId
    },
    changeXOnly: XO(agentA)
  });
  assert.equal(req.txId, direct.txId, "same txid with and without the reservation layer");
  assert.equal(JSON.stringify(req.build.frozenCanonicalJson), JSON.stringify(direct.frozenCanonicalJson), "identical frozen bytes");
  // reject + rebuild: byte-identical again (the reservation layer never perturbs the builder)
  await markWalletRejected(config, req.requestId);
  const again = await buildSpend(7n);
  assert.equal(again.txId, req.txId);
  await markWalletRejected(config, again.requestId);
});

test("UNIT: owner operation takes NO reservation", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "ownerPause",
    params: { fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` } },
    signerAddress: ADDR(owner)
  });
  assert.equal(req.state, RequestState.BUILT);
  assert.equal(req.reservationKey, null);
  assert.equal((await listResv()).length, 0);
  await markWalletRejected(config, req.requestId);
});

test("UNIT: above-threshold spend holds its reservation while AWAITING_APPROVALS", async () => {
  await seedManifest([tightEntry({ approvalThreshold: (5n * KAS).toString() })], { approvers: approvers.map(XO), approvalM: "2" });
  const req = await buildSpend(6n, {
    fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agentA)}ac` }
  });
  assert.equal(req.state, RequestState.AWAITING_APPROVALS);
  const resv = await listResv();
  assert.equal(resv.length, 1);
  assert.equal(resv[0].status, "ACTIVE");
  await markWalletRejected(config, req.requestId);
  assert.equal((await listResv()).length, 0);
});

/* ------------------------------------------------------------------ */
/* ADVERSARIAL — concurrency, release, consume                         */
/* ------------------------------------------------------------------ */

test("ADVERSARIAL: two CONCURRENT builds summing over the period budget — exactly one BUILT, one BUDGET_RESERVED_EXCEEDED naming the holder", async () => {
  await seedManifest([tightEntry()]); // budget 30, spends 20 + 20
  const results = await Promise.allSettled([buildSpend(20n), buildSpend(20n)]);
  const ok = results.filter((r) => r.status === "fulfilled");
  const failed = results.filter((r) => r.status === "rejected");
  assert.equal(ok.length, 1, `exactly one build wins (got ${JSON.stringify(results.map((r) => r.status))})`);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.code, "BUDGET_RESERVED_EXCEEDED");
  const winner = ok[0].value;
  assert.ok(failed[0].reason.message.includes(winner.requestId), "the refusal names the holding requestId");
  assert.ok(failed[0].reason.message.includes((20n * KAS).toString()), "the refusal states the reserved amount");
  const resv = await listResv();
  assert.equal(resv.length, 1, "exactly one reservation exists");
  assert.equal(resv[0].requestId, winner.requestId);
  // the loser persisted NOTHING durable
  const all = await store().listValues(Categories.REQUEST);
  const mine = all.filter((r) => r && r.vaultId === VAULT_ID && r.state === "BUILT");
  assert.equal(mine.length, 1, "the refused build left no durable request");
  await markWalletRejected(config, winner.requestId);
});

test("ADVERSARIAL: sequential build -> reject -> rebuild (release works end-to-end)", async () => {
  await seedManifest([tightEntry()]);
  const first = await buildSpend(20n);
  await assert.rejects(() => buildSpend(20n), (e) => e.code === "BUDGET_RESERVED_EXCEEDED");
  await markWalletRejected(config, first.requestId);
  assert.equal((await loadRequest(config, first.requestId)).state, RequestState.WALLET_REJECTED);
  const second = await buildSpend(20n); // freed headroom admits the rebuild
  assert.equal(second.state, RequestState.BUILT);
  await markWalletRejected(config, second.requestId);
});

test("ADVERSARIAL: finalize CONSUMES; consumed keeps counting until the manifest advances; exact-boundary admission", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  const done = await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: devSign(req, agentA) });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
  const resv = await listResv();
  assert.equal(resv.length, 1);
  assert.equal(resv[0].status, "CONSUMED");
  assert.equal(resv[0].txId, done.txId, "consumption ties the finalized txid");
  // consumed still counts: another 20 would make 40 > 30
  await assert.rejects(() => buildSpend(20n), (e) => e.code === "BUDGET_RESERVED_EXCEEDED");
  // exact boundary: 20 consumed + 10 = 30 <= 30 admits
  const fill = await buildSpend(10n);
  assert.equal(fill.state, RequestState.BUILT);
  // and now the window is exactly full — 1 more KAS refuses, naming BOTH holders
  await assert.rejects(
    () => buildSpend(1n),
    (e) => e.code === "BUDGET_RESERVED_EXCEEDED" && e.message.includes(req.requestId) && e.message.includes(fill.requestId)
  );
  await markWalletRejected(config, fill.requestId);
  // NOTE: req is PREFLIGHT_VERIFIED (claims held) — its reservation stays
  // CONSUMED until a manifest advance or reconciliation releases it; the
  // next test re-seeds (new outpoint), which sweeps it as context-stale.
});

test("ADVERSARIAL: rollover (periodsElapsed >= 1) reserves the NEW window — independent of the current window's reservations", async () => {
  await seedManifest([tightEntry()]);
  const current = await buildSpend(20n); // window 541000000
  const rolled = await buildSpend(20n, { periodsElapsed: "1" }); // window 541864000: fresh budget
  assert.equal(rolled.state, RequestState.BUILT);
  const resv = (await listResv()).sort((a, b) => a.windowStartDaa.localeCompare(b.windowStartDaa));
  assert.equal(resv.length, 2);
  assert.deepEqual(resv.map((r) => r.windowStartDaa), ["541000000", "541864000"]);
  // the rolled window fills independently: another rolled 20 would be 40 > 30
  await assert.rejects(() => buildSpend(20n, { periodsElapsed: "1" }), (e) => e.code === "BUDGET_RESERVED_EXCEEDED");
  await markWalletRejected(config, current.requestId);
  await markWalletRejected(config, rolled.requestId);
});

/* ------------------------------------------------------------------ */
/* CRASH-RECOVERY — deterministic sweep reclaims                       */
/* ------------------------------------------------------------------ */

test("CRASH-RECOVERY: an ACTIVE orphan (reservation without a durable request, past the stale deadline) is reclaimed by the sweep", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  const key = req.reservationKey;
  // simulate the crash inverse: the request record vanished, the reservation stayed
  await store().remove(Categories.REQUEST, req.requestId);
  const record = (await listResv())[0];
  await store().write(Categories.TRANSITION_CLAIM, key, { ...record, key: undefined, createdAtMs: Date.now() - 6 * 60 * 1000 });
  // headroom only exists if the orphan is swept: 20 + 20 > 30
  const next = await buildSpend(20n);
  assert.equal(next.state, RequestState.BUILT);
  const resv = await listResv();
  assert.equal(resv.length, 1);
  assert.equal(resv[0].requestId, next.requestId, "the orphan was reclaimed, not counted");
  await markWalletRejected(config, next.requestId);
});

test("CRASH-RECOVERY: a FRESH orphan is NOT reclaimed (still counts) — the deadline rule is deterministic", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  await store().remove(Categories.REQUEST, req.requestId); // crashed save, reservation fresh
  await assert.rejects(() => buildSpend(20n), (e) => e.code === "BUDGET_RESERVED_EXCEEDED");
  // manual cleanup for the next test
  await store().remove(Categories.TRANSITION_CLAIM, req.reservationKey);
});

test("CRASH-RECOVERY: a reservation whose request reached a released state (missed release hook) is reclaimed", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  const stored = await loadRequest(config, req.requestId);
  stored.state = "STALE"; // simulate the state write landing without the release (crash between the two)
  await saveRequest(config, stored);
  const next = await buildSpend(20n); // sweep reclaims the dead request's reservation
  assert.equal(next.state, RequestState.BUILT);
  await markWalletRejected(config, next.requestId);
});

test("CRASH-RECOVERY: context sweep — a NEW predecessor outpoint (same stateId) invalidates old reservations", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  assert.equal((await listResv()).length, 1);
  await seedManifest([tightEntry()]); // same registry/state => SAME stateId, NEW outpoint
  const next = await buildSpend(20n); // old reservation is context-stale: swept, not counted
  assert.equal(next.state, RequestState.BUILT);
  const resv = await listResv();
  assert.equal(resv.length, 1);
  assert.equal(resv[0].requestId, next.requestId);
  void req;
  await markWalletRejected(config, next.requestId);
});

/* ------------------------------------------------------------------ */
/* ADVERSARIAL — forgery / unknown versions / corruption fail closed   */
/* ------------------------------------------------------------------ */

test("ADVERSARIAL: a reservation cannot be consumed cross-request; a doctored owner field fails closed", async () => {
  await seedManifest([tightEntry()]);
  const req = await buildSpend(20n);
  // a DIFFERENT request (fresh id) consuming: reads its OWN key -> legacy no-op, victim untouched
  const impostor = { schema: "policyvault-wallet-request/v4", sdkAction: "agentSpend", vaultId: VAULT_ID, agentPk: XO(agentA), requestId: "00000000-0000-4000-8000-000000000000" };
  const res = await consumeReservationForRequest(config, impostor, { txId: "ff".repeat(32) });
  assert.equal(res.consumed, false);
  assert.equal((await listResv())[0].status, "ACTIVE", "the victim reservation is untouched");
  // a doctored record (requestId swapped inside the record) fails closed on consume
  const record = (await listResv())[0];
  await store().write(Categories.TRANSITION_CLAIM, req.reservationKey, { ...record, key: undefined, requestId: impostor.requestId });
  await assert.rejects(
    async () => consumeReservationForRequest(config, await loadRequest(config, req.requestId), { txId: "ff".repeat(32) }),
    (e) => e.code === "RESERVATION_FORGERY"
  );
  await store().remove(Categories.TRANSITION_CLAIM, req.reservationKey);
  await markWalletRejected(config, req.requestId);
});

test("ADVERSARIAL: an UNKNOWN reservation schema version in scope refuses admission (never ignored, never defaulted)", async () => {
  await seedManifest([tightEntry()]);
  const alienKey = reservationKey({ vaultId: VAULT_ID, agentPk: XO(agentA), requestId: "11111111-1111-4111-8111-111111111111" });
  await store().write(Categories.TRANSITION_CLAIM, alienKey, { schema: "policyvault-budget-reservation/v99", requestId: "x", amountSompi: "1" });
  await assert.rejects(() => buildSpend(1n), (e) => e.code === "RESERVATION_UNRECOGNIZED");
  await store().remove(Categories.TRANSITION_CLAIM, alienKey);
  const ok = await buildSpend(1n);
  assert.equal(ok.state, RequestState.BUILT);
  await markWalletRejected(config, ok.requestId);
});

test("ADVERSARIAL: a CORRUPT reservation record refuses admission (fail closed, named key) — JSON backend", async () => {
  await seedManifest([tightEntry()]);
  const corruptKey = reservationKey({ vaultId: VAULT_ID, agentPk: XO(agentA), requestId: "22222222-2222-4222-8222-222222222222" });
  const p = path.join(dataRoot, "claims", "transition", `${corruptKey}.json`);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, "{ not json !!!");
  await assert.rejects(() => buildSpend(1n), (e) => e.code === "RESERVATION_RECORD_CORRUPT" && e.message.includes(corruptKey));
  fs.unlinkSync(p);
  const ok = await buildSpend(1n);
  assert.equal(ok.state, RequestState.BUILT);
  await markWalletRejected(config, ok.requestId);
});

test("ADVERSARIAL: admission lock — a crashed (stale) holder is reclaimed; a live holder makes the build fail closed RESERVATION_BUSY", async () => {
  await seedManifest([tightEntry()]);
  const lockKey = `resvlock-${VAULT_ID}`;
  // stale holder: reclaimed transparently
  await store().write(Categories.TRANSITION_CLAIM, lockKey, { schema: RESERVATION_LOCK_SCHEMA, vaultId: VAULT_ID, holderRequestId: "crashed", createdAt: new Date(0).toISOString(), createdAtMs: Date.now() - 60_000 });
  const ok = await buildSpend(1n);
  assert.equal(ok.state, RequestState.BUILT);
  await markWalletRejected(config, ok.requestId);
  // live holder: bounded wait then RESERVATION_BUSY (pure refusal)
  await store().write(Categories.TRANSITION_CLAIM, lockKey, { schema: RESERVATION_LOCK_SCHEMA, vaultId: VAULT_ID, holderRequestId: "live", createdAt: new Date().toISOString(), createdAtMs: Date.now() });
  await assert.rejects(() => buildSpend(1n), (e) => e.code === "RESERVATION_BUSY");
  await store().remove(Categories.TRANSITION_CLAIM, lockKey);
});

/* ------------------------------------------------------------------ */
/* SIMULATE — zero persistence proof                                   */
/* ------------------------------------------------------------------ */

test("SIMULATE: the dry-run path takes NO reservation and persists NOTHING (dataRoot snapshot proof)", async () => {
  await seedManifest([tightEntry()]);
  const { simulateWalletRequestV4 } = require("../../server/src/simulate");
  const snapshot = () => {
    const files = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else files.push(`${path.relative(dataRoot, p)}:${fs.statSync(p).size}`);
      }
    };
    walk(dataRoot);
    return files.sort().join("\n");
  };
  const before = snapshot();
  const out = await simulateWalletRequestV4(config, { vaultId: VAULT_ID, action: "agentSpend", params: spendParams(20n), signerAddress: ADDR(agentA) });
  assert.equal(out.ok, true, `simulation itself succeeds: ${JSON.stringify(out.refusalReason ?? null)}`);
  assert.equal(snapshot(), before, "simulate persisted NOTHING — no request, no reservation, no lock residue");
  assert.equal((await listResv()).length, 0);
});
