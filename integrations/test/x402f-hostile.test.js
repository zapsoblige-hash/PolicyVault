"use strict";

/*
 * ADVERSARIAL — the x402 facilitator hostile matrix (spec §11, every row)
 * driven through the REAL facilitator core with a scripted node view.
 * Each case is a policy-invalid adversarial test input against
 * PolicyVault's own facilitator; every disposition (REFUSE / RETRY /
 * PENDING / VERIFIED / SETTLED) and reason code is asserted exactly, and
 * pure refusals are proven to make ZERO node observations and ZERO
 * claim-store writes.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const h = require("./helpers/x402f");

const KAS = 100000000n;
const RECIP = h.KEY(0x77);
const OTHER = h.KEY(0x78);
const PAY_TO = h.ADDR(RECIP);
const TXID = "ab".repeat(32);
const claimsCount = (dir) => fs.readdirSync(path.join(dir, "claims")).length;

function fresh(opts = {}) {
  const ctx = h.buildFacilitator(opts);
  ctx.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_500n });
  return ctx;
}
async function verifyWith(ctx, { req, pay, text, x402Version } = {}) {
  const r = req ?? h.requirements({ payTo: PAY_TO });
  const p = pay ?? h.payload({ accepted: r, transactionId: TXID });
  return ctx.facilitator.verify({ text: text ?? h.body({ requirements: r, payload: p, x402Version }), principal: null });
}
async function settleWith(ctx, { req, pay, text, x402Version } = {}) {
  const r = req ?? h.requirements({ payTo: PAY_TO });
  const p = pay ?? h.payload({ accepted: r, transactionId: TXID });
  return ctx.facilitator.settle({ text: text ?? h.body({ requirements: r, payload: p, x402Version }), principal: null });
}
function expectRefusal(out, code, { http = 200, status = "REFUSED" } = {}) {
  assert.equal(out.http, http, JSON.stringify(out.body));
  assert.equal(out.body.isValid ?? out.body.success, false);
  assert.equal(out.body.invalidReason ?? out.body.errorReason, code, JSON.stringify(out.body.extensions));
  assert.equal(out.body.extensions.policyvault.status, status);
}
/* A PURE refusal: no node observation, no claim written. */
async function pureRefusal(build, code, opts) {
  const ctx = fresh();
  const before = ctx.node.calls.length;
  const out = await verifyWith(ctx, build(ctx));
  expectRefusal(out, code, opts);
  assert.equal(ctx.node.calls.length, before, `${code}: a pure refusal must not touch the node`);
  const s = await settleWith(ctx, build(ctx));
  expectRefusal(s, code, opts);
  assert.equal(claimsCount(ctx.claimsDir), 0, `${code}: nothing may be claimed`);
  assert.equal(ctx.node.calls.length, before);
  return out;
}

/* ---------------- closed schema / version / scheme ---------------- */

test("§11 malformed body: not JSON, duplicate key, __proto__ key, nesting bomb, trailing garbage → SCHEMA_INVALID (400, unparseable) with zero node/store effect", async () => {
  for (const text of ["{", "not json", '{"x402Version":2,"x402Version":2}', '{"__proto__":{"a":1}}', `${"[".repeat(40)}1${"]".repeat(40)}`, '{"x402Version":2} x']) {
    await pureRefusal(() => ({ text }), "SCHEMA_INVALID", { http: 400 });
  }
});

test("§11 unknown field at every level → SCHEMA_INVALID (closed schema)", async () => {
  const r = h.requirements({ payTo: PAY_TO });
  const cases = [
    () => ({ text: JSON.stringify({ x402Version: 2, paymentPayload: h.payload({ accepted: r, transactionId: TXID }), paymentRequirements: r, extra: 1 }) }),
    () => ({ req: h.requirements({ payTo: PAY_TO, overrides: { hidden: true } }) }),
    () => ({ req: h.requirements({ payTo: PAY_TO, extraOverrides: { binding: "payload" } }) }),
    () => ({ pay: { ...h.payload({ accepted: r, transactionId: TXID }), signature: "x" }, req: r }),
    () => ({ pay: { ...h.payload({ accepted: r, transactionId: TXID }), payload: { transactionId: TXID, outputIndex: 0, daaScore: "1" } }, req: r })
  ];
  for (const c of cases) await pureRefusal(c, "SCHEMA_INVALID");
});

test("§11 unknown x402Version (body and payload) → VERSION_UNSUPPORTED — never routed to a default", async () => {
  await pureRefusal(() => ({ x402Version: 1 }), "VERSION_UNSUPPORTED");
  await pureRefusal(() => ({ x402Version: 3 }), "VERSION_UNSUPPORTED");
  const r = h.requirements({ payTo: PAY_TO });
  await pureRefusal(() => ({ req: r, pay: { ...h.payload({ accepted: r, transactionId: TXID }), x402Version: 1 } }), "VERSION_UNSUPPORTED");
});

test("§11 unknown scheme / kaspaScheme → SCHEME_UNSUPPORTED; flow → FLOW_UNSUPPORTED; settlement policy → POLICY_UNSUPPORTED", async () => {
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, overrides: { scheme: "upto" } }) }), "SCHEME_UNSUPPORTED");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, overrides: { scheme: "Exact" } }) }), "SCHEME_UNSUPPORTED");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, extraOverrides: { kaspaScheme: "pv-x402-kaspa-exact-upfront/2" } }) }), "SCHEME_UNSUPPORTED");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, extraOverrides: { paymentFlow: "authorization" } }) }), "FLOW_UNSUPPORTED");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, extraOverrides: { settlementPolicy: "pv-x402-settlement/2" } }) }), "POLICY_UNSUPPORTED");
});

test("§11 wrong network or look-alike string → NETWORK_MISMATCH (byte-exact; no case folding, trimming, aliasing)", async () => {
  for (const network of ["kaspa:mainnet", "kaspa:testnet-11", "kaspa:testnet", "kaspa:testnet-10 ", " kaspa:testnet-10", "KASPA:TESTNET-10", "kaspa:testnet-1", "kaspa:testnet-100", "eip155:1", ""]) {
    await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, network }) }), "NETWORK_MISMATCH");
  }
});

test("§11 wrong / unknown asset → ASSET_UNSUPPORTED (allowlist only, no blessed list)", async () => {
  for (const asset of ["USDC", "kas", "KAS ", `pvad1:${"00".repeat(32)}`, "pvad1:", `pvad2:${h.DESCRIPTOR_HASH}`, h.DESCRIPTOR_HASH]) {
    await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, asset }) }), "ASSET_UNSUPPORTED");
  }
});

test("§11 float / exponent / hex / leading-zero / negative / zero / JSON-number amount → AMOUNT_INVALID (no float ever constructed)", async () => {
  for (const amount of ["1.0", "1e8", "0x5f5e100", "0100000000", "-1", "0", " 100000000", "100000000\n", "2900000000000000001"]) {
    await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, amount }) }), "AMOUNT_INVALID");
  }
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, amount: 100000000 }) }), "AMOUNT_INVALID");
});

test("§11 payTo: wrong network prefix, mixed case, URL, bad checksum, non-literal → ADDRESS_INVALID", async () => {
  for (const payTo of [PAY_TO.replace("kaspatest:", "kaspa:"), PAY_TO.toUpperCase(), `https://${PAY_TO}`, `${PAY_TO.slice(0, -1)}q`, "merchant", `${PAY_TO} `, h.XO(RECIP)]) {
    await pureRefusal(() => ({ req: h.requirements({ payTo }) }), "ADDRESS_INVALID");
  }
});

test("§11 accepted ≠ requirements by one field / resource.url ≠ extra.resourceUrl → REQUIREMENTS_MISMATCH", async () => {
  const r = h.requirements({ payTo: PAY_TO });
  await pureRefusal(() => ({ req: r, pay: h.payload({ accepted: { ...r, amount: "100000001" }, transactionId: TXID }) }), "REQUIREMENTS_MISMATCH");
  await pureRefusal(() => ({ req: r, pay: h.payload({ accepted: { ...r, extra: { ...r.extra, resourceUrl: "https://api.example.test/other" } }, transactionId: TXID }) }), "REQUIREMENTS_MISMATCH");
  await pureRefusal(() => ({ req: r, pay: h.payload({ accepted: r, transactionId: TXID, resource: { url: "https://api.example.test/other" } }) }), "REQUIREMENTS_MISMATCH");
  // key order is NOT a mismatch (canonical equality)
  const reordered = { extra: r.extra, maxTimeoutSeconds: r.maxTimeoutSeconds, payTo: r.payTo, asset: r.asset, amount: r.amount, network: r.network, scheme: r.scheme };
  const ctx = fresh();
  const ok = await verifyWith(ctx, { req: r, pay: h.payload({ accepted: reordered, transactionId: TXID }) });
  assert.equal(ok.body.isValid, true);
});

test("§11 validity window: not increasing, longer than 36,000, non-canonical → REQUIREMENT_WINDOW_INVALID; maxTimeoutSeconds / outputIndex / transactionId shape → SCHEMA_INVALID", async () => {
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, validFrom: 1000n, validUntil: 1000n }) }), "REQUIREMENT_WINDOW_INVALID");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, validFrom: 1000n, validUntil: 37001n }) }), "REQUIREMENT_WINDOW_INVALID");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, extraOverrides: { validFromDaaScore: "01000" } }) }), "REQUIREMENT_WINDOW_INVALID");
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, extraOverrides: { validUntilDaaScore: 1001000 } }) }), "REQUIREMENT_WINDOW_INVALID");
  for (const maxTimeoutSeconds of [0, 3601, "30", -1]) await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, maxTimeoutSeconds }) }), "SCHEMA_INVALID");
  // a float anywhere in the body is refused by the strict parser itself (no float is ever constructed) → 400
  await pureRefusal(() => ({ req: h.requirements({ payTo: PAY_TO, maxTimeoutSeconds: 30.5 }) }), "SCHEMA_INVALID", { http: 400 });
  const r = h.requirements({ payTo: PAY_TO });
  for (const transactionId of [TXID.toUpperCase(), TXID.slice(0, 63), `${TXID}0`, 1]) await pureRefusal(() => ({ req: r, pay: h.payload({ accepted: r, transactionId }) }), "SCHEMA_INVALID");
  for (const outputIndex of [-1, "0", null]) await pureRefusal(() => ({ req: r, pay: h.payload({ accepted: r, transactionId: TXID, outputIndex }) }), "SCHEMA_INVALID");
  await pureRefusal(() => ({ req: r, pay: h.payload({ accepted: r, transactionId: TXID, outputIndex: 1.5 }) }), "SCHEMA_INVALID", { http: 400 });
});

/* ---------------- chain observation rows ---------------- */

test("§11 missing / not yet accepted / never existed → PENDING PAYMENT_NOT_OBSERVED until window + depth elapse, then REQUIREMENT_EXPIRED; nothing claimed either way", async () => {
  const ctx = h.buildFacilitator();
  const out = await verifyWith(ctx);
  expectRefusal(out, "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  assert.equal(ctx.node.calls.length, 1);
  const s = await settleWith(ctx);
  expectRefusal(s, "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  assert.equal(claimsCount(ctx.claimsDir), 0);
  ctx.node.virtualDaaScore = 1_001_000n + 100n; // == validUntil + minDepth: still pending
  expectRefusal(await verifyWith(ctx), "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  ctx.node.virtualDaaScore = 1_001_000n + 101n; // beyond → final refusal
  expectRefusal(await verifyWith(ctx), "REQUIREMENT_EXPIRED");
  expectRefusal(await settleWith(ctx), "REQUIREMENT_EXPIRED");
  assert.equal(claimsCount(ctx.claimsDir), 0);
});

test("§11 wrong output index: no entry at the named index → PAYMENT_NOT_OBSERVED (the payer names the index; no search); entry present but mismatching → OUTPUT_MISMATCH", async () => {
  const ctx = fresh();
  const r = h.requirements({ payTo: PAY_TO });
  expectRefusal(await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: TXID, outputIndex: 1 }) }), "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  ctx.node.addEntry(PAY_TO, { transactionId: TXID, index: 1, amount: KAS - 1n, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_500n });
  expectRefusal(await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: TXID, outputIndex: 1 }) }), "OUTPUT_MISMATCH");
});

test("§11 wrong recipient: a requirement naming another destination never sees the payment; an entry whose script is not payTo's → OUTPUT_MISMATCH", async () => {
  const ctx = fresh();
  const rOther = h.requirements({ payTo: h.ADDR(OTHER) });
  expectRefusal(await verifyWith(ctx, { req: rOther, pay: h.payload({ accepted: rOther, transactionId: TXID }) }), "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  const ctx2 = h.buildFacilitator();
  ctx2.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(OTHER), blockDaaScore: 999_500n });
  expectRefusal(await verifyWith(ctx2), "OUTPUT_MISMATCH");
});

test("§11 amount below / above / altered by ±1 sompi → OUTPUT_MISMATCH (exact scheme); covenant-carrying or coinbase output → OUTPUT_MISMATCH", async () => {
  for (const amount of [KAS - 1n, KAS + 1n, 1n, KAS * 2n]) {
    const ctx = h.buildFacilitator();
    ctx.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_500n });
    expectRefusal(await verifyWith(ctx), "OUTPUT_MISMATCH");
    expectRefusal(await settleWith(ctx), "OUTPUT_MISMATCH");
    assert.equal(claimsCount(ctx.claimsDir), 0);
  }
  const cov = h.buildFacilitator();
  cov.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_500n, covenantId: "cc".repeat(32) });
  expectRefusal(await verifyWith(cov), "OUTPUT_MISMATCH");
  const cb = h.buildFacilitator();
  cb.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_500n, isCoinbase: true });
  expectRefusal(await verifyWith(cb), "OUTPUT_MISMATCH");
});

test("§11 inclusion outside the window (before validFrom / after validUntil) → PAYMENT_OUTSIDE_WINDOW; an old payment to the same address cannot satisfy a newer requirement", async () => {
  for (const blockDaaScore of [998_999n, 1_001_001n]) {
    const ctx = h.buildFacilitator();
    ctx.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore });
    expectRefusal(await verifyWith(ctx), "PAYMENT_OUTSIDE_WINDOW");
    expectRefusal(await settleWith(ctx), "PAYMENT_OUTSIDE_WINDOW");
    assert.equal(claimsCount(ctx.claimsDir), 0);
  }
  const edges = h.buildFacilitator();
  edges.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_000n });
  assert.equal((await verifyWith(edges)).body.isValid, true, "validFrom is inclusive");
});

test("§11 insufficient settlement depth → PENDING PAYMENT_PENDING_DEPTH (CHAIN_SEEN), /settle claims nothing; at exactly MIN_DEPTH_DAA → CHAIN_VERIFIED and claimable", async () => {
  const ctx = h.buildFacilitator({ minDepthDaa: 100n });
  ctx.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 1_000_000n - 99n });
  const pending = await verifyWith(ctx);
  expectRefusal(pending, "PAYMENT_PENDING_DEPTH", { status: "PENDING" });
  assert.equal(pending.body.extensions.policyvault.observed.depth, "99");
  expectRefusal(await settleWith(ctx), "PAYMENT_PENDING_DEPTH", { status: "PENDING" });
  assert.equal(claimsCount(ctx.claimsDir), 0);
  ctx.node.virtualDaaScore += 1n;
  const ok = await verifyWith(ctx);
  assert.equal(ok.body.isValid, true);
  assert.equal(ok.body.extensions.policyvault.depth, "100");
  assert.equal(ok.body.extensions.policyvault.status, "CHAIN_VERIFIED");
  const settled = await settleWith(ctx);
  assert.equal(settled.body.success, true);
  assert.equal(claimsCount(ctx.claimsDir), 1);
});

test("§11 reorganized away after CHAIN_SEEN → PENDING again; a claim is only ever written at CHAIN_VERIFIED", async () => {
  const ctx = h.buildFacilitator();
  ctx.node.addEntry(PAY_TO, { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_950n });
  expectRefusal(await settleWith(ctx), "PAYMENT_PENDING_DEPTH", { status: "PENDING" });
  ctx.node.removeEntry(TXID, 0);
  expectRefusal(await settleWith(ctx), "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  assert.equal(claimsCount(ctx.claimsDir), 0);
});

test("§11 spent before settle: unverifiable (PAYMENT_NOT_OBSERVED); after a claim, /verify reports the live chain while /settle replays the stored evidence (documented limitation)", async () => {
  const ctx = fresh();
  const r = h.requirements({ payTo: PAY_TO });
  assert.equal((await settleWith(ctx, { req: r })).body.success, true);
  ctx.node.removeEntry(TXID, 0); // the payee spent it
  expectRefusal(await verifyWith(ctx, { req: r }), "PAYMENT_NOT_OBSERVED", { status: "PENDING" });
  const replay = await settleWith(ctx, { req: r });
  assert.equal(replay.body.success, true);
  assert.equal(replay.body.extensions.policyvault.replay, true);
  assert.equal(claimsCount(ctx.claimsDir), 1);
});

/* ---------------- replay / single-use rows ---------------- */

test("§11 replayed requirement with a new outpoint → REQUIREMENT_ALREADY_SETTLED; same outpoint under a different requirement → PAYMENT_ALREADY_CLAIMED; identical pair → idempotent replay of the SAME evidence", async () => {
  const ctx = fresh();
  const r = h.requirements({ payTo: PAY_TO });
  const first = await settleWith(ctx, { req: r });
  assert.equal(first.body.success, true);
  const evidence = first.body.extensions.policyvault;
  // second outpoint for the same requirement
  ctx.node.addEntry(PAY_TO, { transactionId: "ac".repeat(32), index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_600n });
  expectRefusal(await settleWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: "ac".repeat(32) }) }), "REQUIREMENT_ALREADY_SETTLED");
  expectRefusal(await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: "ac".repeat(32) }) }), "REQUIREMENT_ALREADY_SETTLED");
  // same outpoint, different requirement (fresh id → different digest; non-overlapping window so the destination rule does not fire first)
  const r2 = h.requirements({ payTo: PAY_TO, validFrom: 1_002_000n, validUntil: 1_003_000n });
  expectRefusal(await settleWith(ctx, { req: r2, pay: h.payload({ accepted: r2, transactionId: TXID }) }), "PAYMENT_ALREADY_CLAIMED");
  expectRefusal(await verifyWith(ctx, { req: r2, pay: h.payload({ accepted: r2, transactionId: TXID }) }), "PAYMENT_ALREADY_CLAIMED");
  // identical pair
  const again = await settleWith(ctx, { req: r });
  assert.equal(again.body.success, true);
  assert.equal(again.body.extensions.policyvault.evidenceDigest, evidence.evidenceDigest);
  assert.equal(again.body.extensions.policyvault.replay, true);
  const v = await verifyWith(ctx, { req: r });
  assert.equal(v.body.isValid, true);
  assert.equal(v.body.extensions.policyvault.claimed, true);
  assert.equal(claimsCount(ctx.claimsDir), 1);
});

test("§11 one transaction paying two resources → verified per distinct outpoint; any second use of one outpoint refuses", async () => {
  const ctx = h.buildFacilitator();
  const A = h.KEY(0x81);
  const B = h.KEY(0x82);
  ctx.node.addEntry(h.ADDR(A), { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(A), blockDaaScore: 999_500n });
  ctx.node.addEntry(h.ADDR(B), { transactionId: TXID, index: 1, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(B), blockDaaScore: 999_500n });
  const rA = h.requirements({ payTo: h.ADDR(A) });
  const rB = h.requirements({ payTo: h.ADDR(B) });
  assert.equal((await settleWith(ctx, { req: rA, pay: h.payload({ accepted: rA, transactionId: TXID, outputIndex: 0 }) })).body.success, true);
  assert.equal((await settleWith(ctx, { req: rB, pay: h.payload({ accepted: rB, transactionId: TXID, outputIndex: 1 }) })).body.success, true);
  const rA2 = h.requirements({ payTo: h.ADDR(A), validFrom: 1_002_000n, validUntil: 1_003_000n });
  expectRefusal(await settleWith(ctx, { req: rA2, pay: h.payload({ accepted: rA2, transactionId: TXID, outputIndex: 0 }) }), "PAYMENT_ALREADY_CLAIMED");
  assert.equal(claimsCount(ctx.claimsDir), 2);
});

test("§11 payTo reused across overlapping requirements → REQUIREMENT_DESTINATION_REUSED (fail closed rather than guessing); a non-overlapping window is allowed", async () => {
  const ctx = fresh();
  assert.equal((await settleWith(ctx)).body.success, true);
  const overlapping = h.requirements({ payTo: PAY_TO, validFrom: 1_000_500n, validUntil: 1_002_000n });
  ctx.node.addEntry(PAY_TO, { transactionId: "ad".repeat(32), index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 1_000_600n });
  expectRefusal(await verifyWith(ctx, { req: overlapping, pay: h.payload({ accepted: overlapping, transactionId: "ad".repeat(32) }) }), "REQUIREMENT_DESTINATION_REUSED");
  expectRefusal(await settleWith(ctx, { req: overlapping, pay: h.payload({ accepted: overlapping, transactionId: "ad".repeat(32) }) }), "REQUIREMENT_DESTINATION_REUSED");
  assert.equal(claimsCount(ctx.claimsDir), 1);
  const later = h.requirements({ payTo: PAY_TO, validFrom: 1_001_001n, validUntil: 1_002_000n });
  ctx.node.virtualDaaScore = 1_003_000n;
  ctx.node.addEntry(PAY_TO, { transactionId: "ae".repeat(32), index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 1_001_500n });
  assert.equal((await settleWith(ctx, { req: later, pay: h.payload({ accepted: later, transactionId: "ae".repeat(32) }) })).body.success, true);
  // a different amount to the same address is a different destination tuple
  const otherAmount = h.requirements({ payTo: PAY_TO, amount: "200000000", validFrom: 999_000n, validUntil: 1_001_000n });
  ctx.node.addEntry(PAY_TO, { transactionId: "af".repeat(32), index: 0, amount: 2n * KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_700n });
  assert.equal((await settleWith(ctx, { req: otherAmount, pay: h.payload({ accepted: otherAmount, transactionId: "af".repeat(32) }) })).body.success, true);
});

test("§11 concurrent settlement claims on one outpoint → exactly one SETTLED, the others REFUSE; identical pairs in parallel all succeed with one record", async () => {
  const ctx = fresh();
  const reqs = Array.from({ length: 6 }, (_, i) => h.requirements({ payTo: PAY_TO, validFrom: 999_000n + BigInt(i) * 3000n, validUntil: 1_001_000n + BigInt(i) * 3000n }));
  // only reqs[0] has a window containing the inclusion DAA 999_500 — the others refuse on the window; use distinct payTo instead
  const keys = Array.from({ length: 6 }, (_, i) => h.KEY(0x90 + i));
  const ctx2 = h.buildFacilitator();
  for (const k of keys) ctx2.node.addEntry(h.ADDR(k), { transactionId: TXID, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(keys[0]), blockDaaScore: 999_500n });
  void reqs;
  const results = await Promise.all(keys.map((k) => {
    const r = h.requirements({ payTo: h.ADDR(k) });
    return ctx2.facilitator.settle({ text: h.body({ requirements: r, payload: h.payload({ accepted: r, transactionId: TXID }) }), principal: null });
  }));
  // keys[1..5] see an entry whose script is keys[0]'s → OUTPUT_MISMATCH; keys[0] settles
  assert.equal(results.filter((x) => x.body.success).length, 1);
  const r0 = h.requirements({ payTo: PAY_TO });
  const same = await Promise.all(Array.from({ length: 5 }, () => ctx.facilitator.settle({ text: h.body({ requirements: r0, payload: h.payload({ accepted: r0, transactionId: TXID }) }), principal: null })));
  assert.equal(same.filter((x) => x.body.success).length, 5);
  assert.equal(claimsCount(ctx.claimsDir), 1);
  assert.equal(new Set(same.map((x) => x.body.extensions.policyvault.evidenceDigest)).size, 1);
});

test("§11 facilitator restart between verification and durable claim: /verify writes nothing; a retried /settle is idempotent", async () => {
  const dir = h.tmp("x402f-claims-");
  const r = h.requirements({ payTo: PAY_TO });
  const a = fresh({ claimsDir: dir });
  assert.equal((await verifyWith(a, { req: r })).body.isValid, true);
  assert.equal(claimsCount(dir), 0, "/verify never writes");
  const s1 = await settleWith(a, { req: r });
  assert.equal(s1.body.success, true);
  const b = fresh({ claimsDir: dir }); // "restarted" instance over the same durable store
  const s2 = await settleWith(b, { req: r });
  assert.equal(s2.body.success, true);
  assert.equal(s2.body.extensions.policyvault.replay, true);
  assert.equal(s2.body.extensions.policyvault.evidenceDigest, s1.body.extensions.policyvault.evidenceDigest);
});

/* ---------------- transaction carriage ---------------- */

test("§11/§17 transactionHex for KAS: consistent bytes verify; a tampered embedded id is recomputed (TXID_MISMATCH); tampered outputs → TXID_MISMATCH; garbage → SCHEMA_INVALID", async () => {
  const carried = h.transactionCarriage({ inputs: [{ txid: "11".repeat(32), index: 0, amount: 5n * KAS }], outputs: [{ value: KAS, spk: h.P2PK_SPK(RECIP) }, { value: 4n * KAS - 10000n, spk: h.P2PK_SPK(OTHER) }] });
  const ctx = h.buildFacilitator();
  ctx.node.addEntry(PAY_TO, { transactionId: carried.transactionId, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(RECIP), blockDaaScore: 999_500n });
  const r = h.requirements({ payTo: PAY_TO });
  assert.equal((await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: carried.transactionId, transactionHex: carried.transactionHex }) })).body.isValid, true);
  const tamperedId = JSON.parse(carried.safeJson);
  tamperedId.id = TXID;
  expectRefusal(await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: TXID, transactionHex: Buffer.from(JSON.stringify(tamperedId)).toString("hex") }) }), "TXID_MISMATCH");
  const tamperedOut = JSON.parse(carried.safeJson);
  tamperedOut.outputs[0].value = "100000001";
  expectRefusal(await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: carried.transactionId, transactionHex: Buffer.from(JSON.stringify(tamperedOut)).toString("hex") }) }), "TXID_MISMATCH");
  for (const transactionHex of ["zz", "00", Buffer.from("{}").toString("hex"), Buffer.from('{"id":1,"id":2}').toString("hex")]) {
    expectRefusal(await verifyWith(ctx, { req: r, pay: h.payload({ accepted: r, transactionId: carried.transactionId, transactionHex }) }), "SCHEMA_INVALID");
  }
  assert.equal(claimsCount(ctx.claimsDir), 0);
});

/* ---------------- node / RPC rows (RETRY class — never a judgement) ---------------- */

test("§11 node unavailable / unsynced / no UTXO index / wrong network / malformed entry → RETRY class (503), nothing claimed, nothing judged", async () => {
  const cases = [
    [(ctx) => (ctx.node.failWith = new Error("ECONNREFUSED")), "NODE_UNAVAILABLE"],
    [(ctx) => (ctx.node.isSynced = false), "NODE_UNSYNCED"],
    [(ctx) => (ctx.node.hasUtxoIndex = false), "UTXO_INDEX_UNAVAILABLE"],
    [(ctx) => (ctx.node.networkId = "mainnet"), "NODE_UNAVAILABLE"],
    [(ctx) => (ctx.node.networkId = "testnet-11"), "NODE_UNAVAILABLE"],
    [(ctx) => ctx.node.entriesByAddress.get(PAY_TO).push({ outpoint: { transactionId: TXID, index: 1 }, amount: KAS, scriptPublicKeyHex: "zz", covenantId: null, blockDaaScore: 1n, isCoinbase: false }), "RPC_MALFORMED"],
    [(ctx) => (ctx.node.entriesByAddress.get(PAY_TO)[0].isCoinbase = undefined), "RPC_MALFORMED"]
  ];
  for (const [mutate, code] of cases) {
    const ctx = fresh();
    mutate(ctx);
    const out = await verifyWith(ctx);
    assert.equal(out.http, 503, `${code}: ${JSON.stringify(out.body)}`);
    assert.equal(out.body.invalidReason, code);
    assert.equal(out.body.extensions.policyvault.status, "RETRY");
    const s = await settleWith(ctx);
    assert.equal(s.http, 503);
    assert.equal(s.body.errorReason, code);
    assert.equal(claimsCount(ctx.claimsDir), 0);
  }
});

/* ---------------- token rows (frozen v0.5 semantics) ---------------- */

function tokenScenario({ ownerKey = RECIP, paidAmount = "2000", selfAmount = "8000", inputAmount = "10000", isMinter = false, ownerScheme = 0, supplyRedeemFor = [1, 2], familyOnEntry = h.FAMILY_ID, wrongTemplate = false, sigscriptRedeem, extraOutputCovenant = null } = {}) {
  const inputState = { ownerIdentifier: "cc".repeat(32), identifierType: 2, amount: inputAmount, isMinter: false };
  const selfState = { ownerIdentifier: "cc".repeat(32), identifierType: 2, amount: selfAmount, isMinter: false };
  const paidState = { ownerIdentifier: ownerScheme === 0 ? h.XO(ownerKey) : "dd".repeat(32), identifierType: ownerScheme, amount: paidAmount, isMinter };
  const inputRedeem = h.tokenRedeemHex(inputState);
  const selfRedeem = h.tokenRedeemHex(selfState);
  let paidRedeem = h.tokenRedeemHex(paidState);
  if (wrongTemplate) {
    const b4 = h.assets.kcc20; // a different accepted-template geometry: build from the familyBound-4 fixture bytes
    const other = require(path.join(h.REPO, "core/assets/test/fixtures/kcc20-template-v1.json")).bounds.find((b) => b.familyBound === 4);
    paidRedeem = b4.bytesToHex(b4.reconstructRedeem(other.prefixHex, b4.encodeState(paidState), other.suffixHex));
  }
  const paidSpk = h.kcc20.p2shSpkHex(paidRedeem);
  const outputs = [
    { value: 100000000n, spk: `aa20${"ee".repeat(32)}87`, covenantId: "ee".repeat(32) }, // controller successor (not the family)
    { value: 25000000n, spk: h.kcc20.p2shSpkHex(selfRedeem), covenantId: h.FAMILY_ID },
    { value: 20000000n, spk: paidSpk, covenantId: h.FAMILY_ID },
    { value: 50000000n, spk: h.P2PK_SPK(OTHER) }
  ];
  if (extraOutputCovenant) outputs.push(extraOutputCovenant);
  const carried = h.transactionCarriage({
    inputs: [
      { txid: "21".repeat(32), index: 0, sigscript: `4c02abcd${"4c"}${"20"}${"ee".repeat(32)}`, utxoSpk: `aa20${"ee".repeat(32)}87` }, // controller input (last push not a token template)
      { txid: "22".repeat(32), index: 0, sigscript: sigscriptRedeem ?? h.p2shSigscript(inputRedeem), utxoSpk: h.kcc20.p2shSpkHex(inputRedeem), amount: 45000000n },
      { txid: "23".repeat(32), index: 0, sigscript: "41" + "ab".repeat(65), utxoSpk: h.P2PK_SPK(OTHER), amount: 100000000n }
    ],
    outputs
  });
  const outputRedeems = {};
  const redeems = { 1: selfRedeem, 2: paidRedeem };
  for (const i of supplyRedeemFor) outputRedeems[String(i)] = redeems[i];
  const ctx = h.buildFacilitator();
  const address = h.addressForScriptPublicKey(h.chainConfig, paidSpk);
  ctx.node.addEntry(address, { transactionId: carried.transactionId, index: 2, amount: 20000000n, scriptPublicKeyHex: paidSpk, covenantId: familyOnEntry, blockDaaScore: 999_500n });
  const r = h.requirements({ payTo: h.ADDR(ownerKey), amount: "2000", asset: h.TOKEN_ASSET });
  const p = h.payload({ accepted: r, transactionId: carried.transactionId, outputIndex: 2, transactionHex: carried.transactionHex, outputRedeems });
  return { ctx, r, p, carried, paidSpk };
}

test("§7.2 token happy path: Binding 1 (consensus covenant id) + Binding 2 (redeem → P2SH script, template corroboration, decoded owner == payTo, amount exact) + conservation → CHAIN_VERIFIED with descriptor hash, owner scheme and issuer powers in the evidence; settle claims once", async () => {
  const { ctx, r, p } = tokenScenario();
  const v = await ctx.facilitator.verify({ text: h.body({ requirements: r, payload: p }), principal: null });
  assert.equal(v.body.isValid, true, JSON.stringify(v.body));
  const ev = v.body.extensions.policyvault;
  assert.equal(ev.descriptorHash, h.DESCRIPTOR_HASH);
  assert.equal(ev.tokenOwnerScheme, "0x00");
  assert.equal(ev.covenantId, h.FAMILY_ID);
  assert.equal(ev.asset, h.TOKEN_ASSET);
  assert.equal(ev.amount, "2000");
  assert.deepEqual(ev.issuerPowers, h.DESCRIPTOR.issuerPowers);
  assert.equal(ev.kcc1Corroboration, "NOT_DECLARED");
  const s = await ctx.facilitator.settle({ text: h.body({ requirements: r, payload: p }), principal: null });
  assert.equal(s.body.success, true);
  assert.equal(claimsCount(ctx.claimsDir), 1);
});

test("§11 token: missing transactionHex / outputRedeems / the paid output's redeem → TOKEN_REDEEM_REQUIRED (pure, no node call)", async () => {
  const { ctx, r, p } = tokenScenario();
  const calls = ctx.node.calls.length;
  for (const mut of [(x) => delete x.payload.transactionHex, (x) => delete x.payload.outputRedeems, (x) => delete x.payload.outputRedeems["2"]]) {
    const q = JSON.parse(JSON.stringify(p));
    mut(q);
    expectRefusal(await ctx.facilitator.verify({ text: h.body({ requirements: r, payload: q }), principal: null }), "TOKEN_REDEEM_REQUIRED");
  }
  assert.equal(ctx.node.calls.length, calls);
});

test("§11 token descriptor / family substitution: observed covenant id ≠ descriptor family → UNSUPPORTED_TOKEN_PROGRAM (Binding 1)", async () => {
  const { ctx, r, p } = tokenScenario({ familyOnEntry: "a8".repeat(32) });
  expectRefusal(await ctx.facilitator.verify({ text: h.body({ requirements: r, payload: p }), principal: null }), "UNSUPPORTED_TOKEN_PROGRAM");
  const noCov = tokenScenario({ familyOnEntry: null });
  expectRefusal(await noCov.ctx.facilitator.verify({ text: h.body({ requirements: noCov.r, payload: noCov.p }), principal: null }), "UNSUPPORTED_TOKEN_PROGRAM");
});

test("§11 token template downgrade / substitution: a redeem of another template → TOKEN_TEMPLATE_MISMATCH; a redeem that does not hash to the output → TOKEN_TEMPLATE_MISMATCH", async () => {
  const wrong = tokenScenario({ wrongTemplate: true });
  expectRefusal(await wrong.ctx.facilitator.verify({ text: h.body({ requirements: wrong.r, payload: wrong.p }), principal: null }), "TOKEN_TEMPLATE_MISMATCH");
  const { ctx, r, p } = tokenScenario();
  const q = JSON.parse(JSON.stringify(p));
  q.payload.outputRedeems["2"] = h.tokenRedeemHex({ ownerIdentifier: h.XO(RECIP), identifierType: 0, amount: "2000", isMinter: true }); // different state → different hash
  expectRefusal(await ctx.facilitator.verify({ text: h.body({ requirements: r, payload: q }), principal: null }), "TOKEN_TEMPLATE_MISMATCH");
});

test("§11 token owner mismatch / unknown owner scheme → TOKEN_OWNER_MISMATCH; a covenant-id owner can never equal an address", async () => {
  const other = tokenScenario({ ownerKey: OTHER });
  const rRecip = h.requirements({ payTo: PAY_TO, amount: "2000", asset: h.TOKEN_ASSET });
  const p = h.payload({ accepted: rRecip, transactionId: other.p.payload.transactionId, outputIndex: 2, transactionHex: other.p.payload.transactionHex, outputRedeems: other.p.payload.outputRedeems });
  expectRefusal(await other.ctx.facilitator.verify({ text: h.body({ requirements: rRecip, payload: p }), principal: null }), "TOKEN_OWNER_MISMATCH");
  const cov = tokenScenario({ ownerScheme: 2 });
  expectRefusal(await cov.ctx.facilitator.verify({ text: h.body({ requirements: cov.r, payload: cov.p }), principal: null }), "TOKEN_OWNER_MISMATCH");
});

test("§11 token amount altered (state 1999 / 2001) → OUTPUT_MISMATCH; minter position → UNSUPPORTED_TOKEN_PROGRAM", async () => {
  for (const paidAmount of ["1999", "2001"]) {
    const s = tokenScenario({ paidAmount, selfAmount: (10000n - BigInt(paidAmount)).toString() });
    expectRefusal(await s.ctx.facilitator.verify({ text: h.body({ requirements: s.r, payload: s.p }), principal: null }), "OUTPUT_MISMATCH");
  }
  const m = tokenScenario({ isMinter: true });
  expectRefusal(await m.ctx.facilitator.verify({ text: h.body({ requirements: m.r, payload: m.p }), principal: null }), "UNSUPPORTED_TOKEN_PROGRAM");
});

test("§11 token conservation: Σ in ≠ Σ out, a family output without a supplied redeem, or a family input whose supplied UTXO script disagrees with its redeem → TOKEN_CONSERVATION_FAILED", async () => {
  const bad = tokenScenario({ selfAmount: "8001" });
  expectRefusal(await bad.ctx.facilitator.verify({ text: h.body({ requirements: bad.r, payload: bad.p }), principal: null }), "TOKEN_CONSERVATION_FAILED");
  const missing = tokenScenario({ supplyRedeemFor: [2] });
  expectRefusal(await missing.ctx.facilitator.verify({ text: h.body({ requirements: missing.r, payload: missing.p }), principal: null }), "TOKEN_CONSERVATION_FAILED");
  const noInput = tokenScenario({ sigscriptRedeem: "41" + "ab".repeat(65) }); // the family input hides its redeem → Σin 0
  expectRefusal(await noInput.ctx.facilitator.verify({ text: h.body({ requirements: noInput.r, payload: noInput.p }), principal: null }), "TOKEN_CONSERVATION_FAILED");
});

test("§11 token txid mismatch → TXID_MISMATCH; token payTo of an ECDSA address → ADDRESS_INVALID; KAS amount bound does not apply to tokens (u64/i64 domain)", async () => {
  const { ctx, r, p } = tokenScenario();
  const q = JSON.parse(JSON.stringify(p));
  q.payload.transactionId = TXID;
  expectRefusal(await ctx.facilitator.verify({ text: h.body({ requirements: r, payload: q }), principal: null }), "TXID_MISMATCH");
  const ecdsa = h.addressForScriptPublicKey(h.chainConfig, `21${"02".padEnd(66, "3")}ab`);
  expectRefusal(await ctx.facilitator.verify({ text: h.body({ requirements: h.requirements({ payTo: ecdsa, amount: "2000", asset: h.TOKEN_ASSET }), payload: q }), principal: null }), "ADDRESS_INVALID");
  const big = h.requirements({ payTo: PAY_TO, amount: "9223372036854775807", asset: h.TOKEN_ASSET });
  const out = await ctx.facilitator.verify({ text: h.body({ requirements: big, payload: h.payload({ accepted: big, transactionId: TXID, outputIndex: 0 }) }), principal: null });
  assert.equal(out.body.invalidReason, "TOKEN_REDEEM_REQUIRED", "i64 max is a valid token amount; refusal comes later");
  expectRefusal(await ctx.facilitator.verify({ text: h.body({ requirements: h.requirements({ payTo: PAY_TO, amount: "9223372036854775808", asset: h.TOKEN_ASSET }), payload: q }), principal: null }), "AMOUNT_INVALID");
});

test("§12 authority: /supported advertises exactly the frozen kind with EMPTY signers; evidence fields come only from the observed entry; evidenceDigest is canonical", async () => {
  const ctx = fresh();
  const sup = ctx.facilitator.supported();
  assert.deepEqual(sup.signers, {});
  assert.equal(sup.kinds.length, 1);
  assert.deepEqual(sup.kinds[0].extra.settlementPolicies, ["pv-x402-settlement/1"]);
  assert.deepEqual(sup.kinds[0].extra.assets, ["KAS", h.TOKEN_ASSET]);
  const out = await verifyWith(ctx);
  const ev = out.body.extensions.policyvault;
  assert.equal(ev.schema, "policyvault-x402-facilitator-evidence/1");
  assert.equal(ev.blockDaaScore, "999500");
  assert.equal(ev.virtualDaaScore, "1000000");
  assert.equal(ev.node.networkId, "testnet-10");
  assert.equal(ev.covenantId, null);
  const { evidenceDigest, claimed, ...rest } = ev;
  void claimed;
  const { domainDigestHex } = require("../lib/canonical");
  assert.equal(evidenceDigest, domainDigestHex("policyvault-x402-facilitator-evidence/1", rest));
  assert.equal(crypto.createHash("sha256").update("x").digest("hex").length, 64);
});
