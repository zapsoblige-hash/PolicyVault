"use strict";

/*
 * INTEGRATION / ADVERSARIAL — the REAL facilitator HTTP service (node:http,
 * real principal store, real JSON claim store, real schema) with a
 * scripted node view: inbound authentication (OQ-F7) and its failure
 * semantics, operation scopes, the mandatory cross-principal negative
 * test, principal constraints, rotation / revocation, rate limits, body
 * caps, query-string refusal, public /supported, and the end-to-end
 * verify → settle → replay flow over the wire.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const h = require("./helpers/x402f");

const KAS = 100000000n;
const A_KEY = h.KEY(0x61);
const B_KEY = h.KEY(0x62);
const PAY_A = h.ADDR(A_KEY);
const PAY_B = h.ADDR(B_KEY);
const TXID_A = "a1".repeat(32);
const TXID_B = "b1".repeat(32);

let ctx;
let svc;
let credA;
let credB;
let credVerifyOnly;
const claimsCount = () => fs.readdirSync(path.join(ctx.claimsDir, "claims")).length;
const bearer = (raw) => ({ Authorization: `Bearer ${raw}` });

before(async () => {
  ctx = h.buildFacilitator();
  ctx.node.addEntry(PAY_A, { transactionId: TXID_A, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(A_KEY), blockDaaScore: 999_500n });
  ctx.node.addEntry(PAY_B, { transactionId: TXID_B, index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(B_KEY), blockDaaScore: 999_500n });
  svc = await h.startService({ facilitator: ctx.facilitator, rateLimitPerMinute: 1000 });
  svc.principals.createPrincipal({ principalId: "merchant-a", operations: ["verify", "settle"], networks: ["kaspa:testnet-10"], allowedPayTo: { mode: "list", addresses: [PAY_A] }, allowedResourceOrigins: { mode: "list", origins: ["https://api.example.test"] } });
  svc.principals.createPrincipal({ principalId: "merchant-b", operations: ["verify", "settle"], networks: ["kaspa:testnet-10"], allowedPayTo: { mode: "list", addresses: [PAY_B] } });
  svc.principals.createPrincipal({ principalId: "verify-only", operations: ["verify"], networks: ["kaspa:testnet-10"], allowedPayTo: { mode: "any" } });
  credA = svc.principals.mintCredential("merchant-a").raw;
  credB = svc.principals.mintCredential("merchant-b").raw;
  credVerifyOnly = svc.principals.mintCredential("verify-only").raw;
});
after(async () => {
  if (svc) await svc.close();
});

const reqA = (over = {}) => h.requirements({ payTo: PAY_A, ...over });
const bodyFor = (r, txid, extra = {}) => h.body({ requirements: r, payload: h.payload({ accepted: r, transactionId: txid, ...extra }) });

test("GET /supported and /healthz are PUBLIC; /supported carries exactly the frozen kind with empty signers", async () => {
  const s = await svc.request("GET", "/supported");
  assert.equal(s.status, 200);
  assert.deepEqual(s.json.signers, {});
  assert.equal(s.json.kinds[0].network, "kaspa:testnet-10");
  assert.equal(s.json.kinds[0].extra.kaspaScheme, "pv-x402-kaspa-exact-upfront/1");
  const hz = await svc.request("GET", "/healthz");
  assert.equal(hz.status, 200);
  assert.equal(hz.json.ok, true);
  assert.equal(svc.request.length >= 0, true);
});

test("§14.1 missing credential → 401 CREDENTIAL_REQUIRED (WWW-Authenticate), before the body is parsed: zero node observations, zero claim writes", async () => {
  const before = ctx.node.calls.length;
  for (const route of ["/verify", "/settle"]) {
    const r = await svc.request("POST", route, { body: bodyFor(reqA(), TXID_A) });
    assert.equal(r.status, 401);
    assert.equal(r.json.invalidReason ?? r.json.errorReason, "CREDENTIAL_REQUIRED");
    assert.match(r.headers["www-authenticate"], /Bearer/);
    assert.equal(r.json.extensions.policyvault.reasonClass, "AUTH");
  }
  assert.equal(ctx.node.calls.length, before);
  assert.equal(claimsCount(), 0);
});

test("§14.1 unknown / malformed / pvmk_ machine credential / session-like / uppercase / Basic scheme → 401 CREDENTIAL_INVALID with zero effect; no downgrade to anonymous", async () => {
  const before = ctx.node.calls.length;
  const bads = [`pvx402f_${"0".repeat(64)}`, `pvmk_${credA.slice(8)}`, credA.toUpperCase(), credA.slice(8), "session=abc", `${credA}0`, credA.slice(0, -1)];
  for (const bad of bads) {
    const r = await svc.request("POST", "/settle", { body: bodyFor(reqA(), TXID_A), headers: bearer(bad) });
    assert.equal(r.status, 401, bad.slice(0, 12));
    assert.equal(r.json.errorReason, "CREDENTIAL_INVALID");
  }
  const basic = await svc.request("POST", "/verify", { body: bodyFor(reqA(), TXID_A), headers: { Authorization: `Basic ${Buffer.from(`x:${credA}`).toString("base64")}` } });
  assert.equal(basic.status, 401);
  assert.equal(ctx.node.calls.length, before);
  assert.equal(claimsCount(), 0);
});

test("§14.1 a valid credential lacking settle authority → 403 SCOPE_FORBIDDEN on /settle (verify still works); zero node/store effect on the refusal", async () => {
  const before = ctx.node.calls.length;
  const r = await svc.request("POST", "/settle", { body: bodyFor(h.requirements({ payTo: PAY_A }), TXID_A), headers: bearer(credVerifyOnly) });
  assert.equal(r.status, 403);
  assert.equal(r.json.errorReason, "SCOPE_FORBIDDEN");
  assert.equal(ctx.node.calls.length, before);
  assert.equal(claimsCount(), 0);
  const v = await svc.request("POST", "/verify", { body: bodyFor(h.requirements({ payTo: PAY_A }), TXID_A), headers: bearer(credVerifyOnly) });
  assert.equal(v.status, 200);
  assert.equal(v.json.isValid, true);
});

test("§14.1 CROSS-PRINCIPAL NEGATIVE: merchant A's valid key cannot verify or settle a requirement whose payTo belongs to B → 403 PRINCIPAL_FORBIDDEN, B's ownership is not disclosed, zero node/store effect, and B can still settle it afterwards", async () => {
  const before = ctx.node.calls.length;
  const rB = h.requirements({ payTo: PAY_B });
  for (const route of ["/verify", "/settle"]) {
    const r = await svc.request("POST", route, { body: bodyFor(rB, TXID_B), headers: bearer(credA) });
    assert.equal(r.status, 403);
    assert.equal(r.json.invalidReason ?? r.json.errorReason, "PRINCIPAL_FORBIDDEN");
    const text = JSON.stringify(r.json);
    assert.ok(!text.includes("merchant-b"), "must not disclose the owning principal");
    assert.ok(!text.includes(PAY_B), "must not echo the foreign destination");
  }
  assert.equal(ctx.node.calls.length, before);
  assert.equal(claimsCount(), 0);
  const ok = await svc.request("POST", "/settle", { body: bodyFor(rB, TXID_B), headers: bearer(credB) });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(ok.json.success, true);
  assert.equal(claimsCount(), 1);
});

test("§14.1 principal constraints: resource origin outside the configured list → 403; a principal configured for kaspa:mainnet only on a testnet-10 facilitator → 403", async () => {
  const wrongOrigin = h.requirements({ payTo: PAY_A, resourceUrl: "https://evil.example.test/data" });
  const r = await svc.request("POST", "/verify", { body: bodyFor(wrongOrigin, TXID_A), headers: bearer(credA) });
  assert.equal(r.status, 403);
  assert.equal(r.json.invalidReason, "PRINCIPAL_FORBIDDEN");
  svc.principals.createPrincipal({ principalId: "mainnet-only", operations: ["verify"], networks: ["kaspa:mainnet"], allowedPayTo: { mode: "any" } });
  const cred = svc.principals.mintCredential("mainnet-only").raw;
  const m = await svc.request("POST", "/verify", { body: bodyFor(h.requirements({ payTo: PAY_A }), TXID_A), headers: bearer(cred) });
  assert.equal(m.status, 403);
  assert.equal(m.json.invalidReason, "PRINCIPAL_FORBIDDEN");
});

test("end-to-end over the wire: verify (CHAIN_VERIFIED, no write) → settle (claim + evidence) → settle again (idempotent replay, same evidence) → verify reports claimed", async () => {
  const rA = h.requirements({ payTo: PAY_A });
  const v = await svc.request("POST", "/verify", { body: bodyFor(rA, TXID_A, { payer: h.ADDR(h.KEY(0x70)) }), headers: bearer(credA) });
  assert.equal(v.status, 200);
  assert.equal(v.json.isValid, true);
  assert.equal(v.json.payer, h.ADDR(h.KEY(0x70)));
  assert.equal(v.json.extensions.policyvault.status, "CHAIN_VERIFIED");
  assert.equal(claimsCount(), 1, "verify wrote nothing (B's earlier claim is the only one)");
  const s = await svc.request("POST", "/settle", { body: bodyFor(rA, TXID_A), headers: bearer(credA) });
  assert.equal(s.status, 200);
  assert.equal(s.json.success, true);
  assert.equal(s.json.transaction, TXID_A);
  assert.equal(s.json.network, "kaspa:testnet-10");
  assert.equal(s.json.amount, "100000000");
  assert.equal(claimsCount(), 2);
  const again = await svc.request("POST", "/settle", { body: bodyFor(rA, TXID_A), headers: bearer(credA) });
  assert.equal(again.json.success, true);
  assert.equal(again.json.extensions.policyvault.replay, true);
  assert.equal(again.json.extensions.policyvault.evidenceDigest, s.json.extensions.policyvault.evidenceDigest);
  const v2 = await svc.request("POST", "/verify", { body: bodyFor(rA, TXID_A), headers: bearer(credA) });
  assert.equal(v2.json.extensions.policyvault.claimed, true);
  assert.equal(claimsCount(), 2);
});

test("§14.1 rotation with overlap keeps the principal; revocation is immediate for new requests; a revoked key's earlier claims are unaffected", async () => {
  const rotated = svc.principals.mintCredential("merchant-a", { allowOverlap: true, label: "rotated" });
  const first = svc.principals.read("merchant-a").credentials[0];
  const rNew = h.requirements({ payTo: PAY_A, validFrom: 1_002_000n, validUntil: 1_003_000n });
  ctx.node.addEntry(PAY_A, { transactionId: "a2".repeat(32), index: 0, amount: KAS, scriptPublicKeyHex: h.P2PK_SPK(A_KEY), blockDaaScore: 1_002_500n });
  ctx.node.virtualDaaScore = 1_003_000n;
  const okNew = await svc.request("POST", "/verify", { body: bodyFor(rNew, "a2".repeat(32)), headers: bearer(rotated.raw) });
  assert.equal(okNew.status, 200, JSON.stringify(okNew.json));
  assert.equal(okNew.json.isValid, true);
  svc.principals.revokeCredential("merchant-a", first.credentialId);
  const old = await svc.request("POST", "/verify", { body: bodyFor(rNew, "a2".repeat(32)), headers: bearer(credA) });
  assert.equal(old.status, 401);
  assert.equal(old.json.invalidReason, "CREDENTIAL_INVALID");
  const stillNew = await svc.request("POST", "/verify", { body: bodyFor(rNew, "a2".repeat(32)), headers: bearer(rotated.raw) });
  assert.equal(stillNew.status, 200);
  credA = rotated.raw;
  assert.equal(claimsCount(), 2, "revocation does not alter payment authority or claims");
});

test("§14.1 rate limit is per principal and availability-only: 429 with Retry-After after the budget; another principal is unaffected; no claim consumed", async () => {
  const tight = h.buildFacilitator();
  const s2 = await h.startService({ facilitator: tight.facilitator, rateLimitPerMinute: 3 });
  try {
    s2.principals.createPrincipal({ principalId: "p1", operations: ["verify"], networks: ["kaspa:testnet-10"], allowedPayTo: { mode: "any" } });
    s2.principals.createPrincipal({ principalId: "p2", operations: ["verify"], networks: ["kaspa:testnet-10"], allowedPayTo: { mode: "any" } });
    const c1 = s2.principals.mintCredential("p1").raw;
    const c2 = s2.principals.mintCredential("p2").raw;
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await s2.request("POST", "/verify", { body: bodyFor(reqA(), TXID_A), headers: bearer(c1) })).status);
    assert.deepEqual(statuses, [200, 200, 200, 429]);
    const limited = await s2.request("POST", "/verify", { body: bodyFor(reqA(), TXID_A), headers: bearer(c1) });
    assert.equal(limited.json.invalidReason, "RATE_LIMITED");
    assert.ok(Number(limited.headers["retry-after"]) >= 1);
    assert.equal((await s2.request("POST", "/verify", { body: bodyFor(reqA(), TXID_A), headers: bearer(c2) })).status, 200);
  } finally {
    await s2.close();
  }
});

test("body cap → 413 BODY_TOO_LARGE; query string → 400 SCHEMA_INVALID even with a valid credential (no credential ever travels in a URL); GET /verify → 405; unknown route → 404", async () => {
  const big = await svc.request("POST", "/verify", { body: `{"x402Version":2,"pad":"${"x".repeat(1024 * 1024 + 10)}"}`, headers: bearer(credA) });
  assert.equal(big.status, 413);
  assert.equal(big.json.invalidReason, "BODY_TOO_LARGE");
  const q = await svc.request("POST", `/verify?token=${credA}`, { body: bodyFor(reqA(), TXID_A), headers: bearer(credA) });
  assert.equal(q.status, 400);
  assert.equal(q.json.invalidReason, "SCHEMA_INVALID");
  const noAuthQ = await svc.request("POST", `/settle?api_key=${credA}`, { body: bodyFor(reqA(), TXID_A) });
  assert.equal(noAuthQ.status, 400);
  assert.equal((await svc.request("GET", "/verify")).status, 405);
  assert.equal((await svc.request("POST", "/x402/attempts", { body: "{}" })).status, 404);
  assert.equal((await svc.request("GET", "/")).status, 404);
});

test("credential hygiene: no log line, no response body, and no principal file ever contains a raw credential", async () => {
  const text = `${JSON.stringify(svc.logs)}\n${fs.readdirSync(svc.principals.dir).map((f) => fs.readFileSync(path.join(svc.principals.dir, f), "utf8")).join("\n")}`;
  for (const raw of [credA, credB, credVerifyOnly]) {
    assert.ok(!text.includes(raw), "raw credential leaked");
    assert.ok(!text.includes(raw.slice(8, 40)), "raw credential body leaked");
  }
  const listed = JSON.stringify(svc.principals.list());
  assert.ok(!listed.includes("verifier"));
});

test("an unparseable body with a valid credential → 400 SCHEMA_INVALID; a valid body reaching a refusal → 200 with the closed code (judgement, not transport)", async () => {
  const bad = await svc.request("POST", "/verify", { body: "{not json", headers: bearer(credA) });
  assert.equal(bad.status, 400);
  assert.equal(bad.json.invalidReason, "SCHEMA_INVALID");
  const wrongNet = h.requirements({ payTo: PAY_A, network: "kaspa:mainnet" });
  const r = await svc.request("POST", "/verify", { body: bodyFor(wrongNet, TXID_A), headers: bearer(credA) });
  assert.equal(r.status, 200);
  assert.equal(r.json.isValid, false);
  assert.equal(r.json.invalidReason, "NETWORK_MISMATCH");
});
