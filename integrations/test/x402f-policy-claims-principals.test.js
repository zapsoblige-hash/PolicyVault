"use strict";

/*
 * UNIT — x402 facilitator settlement policy (decisions A/B), durable
 * single-use claims (JSON store: atomicity, both uniqueness invariants,
 * idempotent replay, crash recovery, destination-reuse index) and the
 * resource-server principal / credential model (OQ-F7).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { resolveMinDepth, resolveSettlementPolicy, validateWindow, classifyDepth, unobservedDisposition, parseDaaString } = require("../x402-facilitator/policy");
const { JsonClaimStore, outpointKey } = require("../x402-facilitator/claims");
const { PrincipalStore, mintCredential, normalizePrincipal } = require("../x402-facilitator/principals");
const { FacilitatorRefusal } = require("../x402-facilitator/codes");
const { MIN_DEPTH_DAA_DEFAULT, MIN_DEPTH_DAA_FLOOR, MAX_WINDOW_DAA, CREDENTIAL_RE } = require("../x402-facilitator/constants");

const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const refuses = (fn, code) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof FacilitatorRefusal, `expected FacilitatorRefusal, got ${e && e.message}`);
    assert.equal(e.code, code);
    return e;
  }
  assert.fail(`expected refusal ${code}`);
};

/* ---------------- policy ---------------- */

test("policy: MIN_DEPTH_DAA defaults to 100, accepts ≥ 20, refuses below the HARD floor and garbage", () => {
  assert.equal(resolveMinDepth(undefined), 100n);
  assert.equal(resolveMinDepth("20"), 20n);
  assert.equal(resolveMinDepth(150), 150n);
  assert.throws(() => resolveMinDepth("19"), /hard floor 20/);
  assert.throws(() => resolveMinDepth("0"), /hard floor/);
  assert.throws(() => resolveMinDepth("-5"), /non-negative integer/);
  assert.throws(() => resolveMinDepth("1e3"), /non-negative integer/);
  assert.throws(() => resolveMinDepth("100.0"), /non-negative integer/);
  assert.equal(MIN_DEPTH_DAA_DEFAULT, 100n);
  assert.equal(MIN_DEPTH_DAA_FLOOR, 20n);
});

test("policy: only pv-x402-settlement/1 is implemented; unknown ids fail closed, never a default", () => {
  const p = resolveSettlementPolicy("pv-x402-settlement/1", { minDepthDaa: 100n });
  assert.equal(p.id, "pv-x402-settlement/1");
  assert.equal(p.maxWindowDaa, MAX_WINDOW_DAA);
  for (const bad of ["pv-x402-settlement/2", "pv-x402-settlement/0", "", null, undefined, 1, "PV-X402-SETTLEMENT/1", "pv-x402-settlement/1 "]) refuses(() => resolveSettlementPolicy(bad), "POLICY_UNSUPPORTED");
});

test("policy: window must be strictly increasing and ≤ MAX_WINDOW_DAA (36,000); inclusion outside fails closed", () => {
  validateWindow(1000n, 1000n + MAX_WINDOW_DAA);
  refuses(() => validateWindow(1000n, 1000n), "REQUIREMENT_WINDOW_INVALID");
  refuses(() => validateWindow(1000n, 999n), "REQUIREMENT_WINDOW_INVALID");
  refuses(() => validateWindow(1000n, 1000n + MAX_WINDOW_DAA + 1n), "REQUIREMENT_WINDOW_INVALID");
  for (const bad of ["01", "1.0", "-1", "1e3", " 1", "", "18446744073709551616"]) refuses(() => parseDaaString(bad, "x"), "SCHEMA_INVALID");
  assert.equal(parseDaaString("18446744073709551615", "x"), 18446744073709551615n);
});

test("policy: depth classification — CHAIN_SEEN below the minimum, CHAIN_VERIFIED at exactly the minimum and above", () => {
  assert.deepEqual(classifyDepth({ virtualDaaScore: 1099n, blockDaaScore: 1000n, minDepthDaa: 100n }), { depth: 99n, status: "CHAIN_SEEN" });
  assert.deepEqual(classifyDepth({ virtualDaaScore: 1100n, blockDaaScore: 1000n, minDepthDaa: 100n }), { depth: 100n, status: "CHAIN_VERIFIED" });
  refuses(() => classifyDepth({ virtualDaaScore: 999n, blockDaaScore: 1000n, minDepthDaa: 100n }), "RPC_MALFORMED");
  assert.equal(unobservedDisposition({ virtualDaaScore: 2100n, validUntil: 2000n, minDepthDaa: 100n }), "PAYMENT_NOT_OBSERVED");
  assert.equal(unobservedDisposition({ virtualDaaScore: 2101n, validUntil: 2000n, minDepthDaa: 100n }), "REQUIREMENT_EXPIRED");
});

/* ---------------- claims ---------------- */

const claimInput = (over = {}) => ({
  requirementDigest: "11".repeat(32),
  network: "kaspa:testnet-10",
  transactionId: "aa".repeat(32),
  outputIndex: 0,
  payTo: "kaspatest:qpuk94zm8r5te7p04rh6sse2q8eqexjnufx860c3muvhew88pynd56n845dz8",
  amount: "100000000",
  asset: "KAS",
  validFromDaaScore: "1000",
  validUntilDaaScore: "2000",
  evidence: { schema: "policyvault-x402-facilitator-evidence/1", status: "CHAIN_VERIFIED" },
  ...over
});

test("claims (JSON): create → read by digest and by outpoint; identical pair replays; the evidence is IN the same record", async () => {
  const store = new JsonClaimStore({ dir: tmp("x402f-claims-") });
  const first = await store.createClaim(claimInput());
  assert.equal(first.created, true);
  assert.equal(first.claim.claimKey, outpointKey("kaspa:testnet-10", "aa".repeat(32), 0));
  const byDigest = await store.readByDigest("11".repeat(32));
  assert.equal(byDigest.evidence.status, "CHAIN_VERIFIED");
  const byOutpoint = await store.readByOutpoint("kaspa:testnet-10", "aa".repeat(32), 0);
  assert.equal(byOutpoint.claim.requirementDigest, "11".repeat(32));
  const again = await store.createClaim(claimInput({ evidence: { different: true } }));
  assert.equal(again.created, false);
  assert.equal(again.reason, "REPLAY");
  assert.equal(again.claim.evidence.status, "CHAIN_VERIFIED", "replay returns the ORIGINAL stored evidence, never new state");
});

test("claims (JSON): second requirement for the same outpoint → PAYMENT_ALREADY_CLAIMED; second outpoint for the same requirement → REQUIREMENT_ALREADY_SETTLED (and the loser's reservation is released)", async () => {
  const dir = tmp("x402f-claims-");
  const store = new JsonClaimStore({ dir });
  await store.createClaim(claimInput());
  const other = await store.createClaim(claimInput({ requirementDigest: "22".repeat(32) }));
  assert.equal(other.created, false);
  assert.equal(other.reason, "PAYMENT_ALREADY_CLAIMED");
  assert.equal(other.claim.requirementDigest, "11".repeat(32));
  const second = await store.createClaim(claimInput({ transactionId: "bb".repeat(32) }));
  assert.equal(second.created, false);
  assert.equal(second.reason, "REQUIREMENT_ALREADY_SETTLED");
  assert.equal(await store.readByOutpoint("kaspa:testnet-10", "bb".repeat(32), 0), null, "the losing outpoint reservation must be released");
  // the released outpoint can still be claimed by another requirement
  const late = await store.createClaim(claimInput({ requirementDigest: "33".repeat(32), transactionId: "bb".repeat(32) }));
  assert.equal(late.created, true);
});

test("claims (JSON): concurrent settles racing on one outpoint → exactly one wins", async () => {
  const store = new JsonClaimStore({ dir: tmp("x402f-claims-") });
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => store.createClaim(claimInput({ requirementDigest: (i + 1).toString(16).padStart(2, "0").repeat(32) }))));
  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(results.filter((r) => !r.created && r.reason === "PAYMENT_ALREADY_CLAIMED").length, 7);
});

test("claims (JSON): crash between the outpoint reservation and the claim → retry of the identical pair completes; a different requirement on that outpoint stays refused", async () => {
  const dir = tmp("x402f-claims-");
  const store = new JsonClaimStore({ dir });
  // simulate: reservation written, process died before the claim file
  fs.writeFileSync(path.join(dir, "outpoints", `${outpointKey("kaspa:testnet-10", "aa".repeat(32), 0)}.json`), JSON.stringify({ requirementDigest: "11".repeat(32), network: "kaspa:testnet-10", transactionId: "aa".repeat(32), outputIndex: 0 }));
  const foreign = await store.createClaim(claimInput({ requirementDigest: "22".repeat(32) }));
  assert.equal(foreign.reason, "PAYMENT_ALREADY_CLAIMED");
  const retry = await store.createClaim(claimInput());
  assert.equal(retry.created, true);
  assert.equal((await store.readByDigest("11".repeat(32))).transactionId, "aa".repeat(32));
});

test("claims (JSON): destination-reuse index finds overlapping windows for the same (network, payTo, amount) and ignores the same digest / non-overlapping / different amount", async () => {
  const store = new JsonClaimStore({ dir: tmp("x402f-claims-") });
  await store.createClaim(claimInput());
  const q = (over) => store.findDestinationConflicts({ network: "kaspa:testnet-10", payTo: claimInput().payTo, amount: "100000000", validFromDaaScore: "1500", validUntilDaaScore: "2500", excludeDigest: "99".repeat(32), ...over });
  assert.equal((await q({})).length, 1);
  assert.equal((await q({ excludeDigest: "11".repeat(32) })).length, 0);
  assert.equal((await q({ validFromDaaScore: "2001", validUntilDaaScore: "3000" })).length, 0);
  assert.equal((await q({ validFromDaaScore: "2000", validUntilDaaScore: "3000" })).length, 1, "touching boundaries overlap");
  assert.equal((await q({ amount: "100000001" })).length, 0);
  assert.equal((await q({ network: "kaspa:mainnet" })).length, 0);
});

test("claims (JSON): records are complete or absent — a torn temp file never lands at the final path", async () => {
  const dir = tmp("x402f-claims-");
  const store = new JsonClaimStore({ dir });
  await store.createClaim(claimInput());
  assert.deepEqual(fs.readdirSync(path.join(dir, "tmp")), [], "temp files are removed");
  for (const f of fs.readdirSync(path.join(dir, "claims"))) JSON.parse(fs.readFileSync(path.join(dir, "claims", f), "utf8"));
  await assert.rejects(store.createClaim(claimInput({ outputIndex: -1 })), /non-negative/);
});

/* ---------------- principals ---------------- */

const principalInput = (over = {}) => ({
  principalId: "merchant-a",
  label: "Merchant A",
  operations: ["verify", "settle"],
  networks: ["kaspa:testnet-10"],
  allowedPayTo: { mode: "list", addresses: ["kaspatest:qpuk94zm8r5te7p04rh6sse2q8eqexjnufx860c3muvhew88pynd56n845dz8"] },
  ...over
});

test("principals: credentials are 256-bit CSPRNG values in the frozen format; only the sha256 verifier is persisted; the raw value is never on disk", () => {
  const dir = tmp("x402f-principals-");
  const store = new PrincipalStore({ dir });
  store.createPrincipal(principalInput());
  const minted = store.mintCredential("merchant-a", { label: "initial" });
  assert.ok(CREDENTIAL_RE.test(minted.raw));
  assert.equal(minted.raw.length, "pvx402f_".length + 64);
  const onDisk = fs.readFileSync(path.join(dir, "merchant-a.json"), "utf8");
  assert.ok(!onDisk.includes(minted.raw), "raw credential must never be persisted");
  assert.ok(!onDisk.includes(minted.raw.slice(8)), "not even the hex body");
  const rec = store.read("merchant-a");
  assert.equal(rec.credentials.length, 1);
  assert.match(rec.credentials[0].verifier, /^[0-9a-f]{64}$/);
  const listed = store.list()[0];
  assert.equal(listed.credentials[0].verifier, undefined, "list/read views carry no verifier");
  assert.equal(JSON.stringify(listed).includes(minted.raw), false);
  const a = mintCredential();
  const b = mintCredential();
  assert.notEqual(a.raw, b.raw);
});

test("principals: authenticate is exact — wrong key, pvmk_ machine credential, session-like strings, whitespace, case all fail; revoked / expired fail; revocation is immediate (re-read per call)", () => {
  const dir = tmp("x402f-principals-");
  const store = new PrincipalStore({ dir });
  store.createPrincipal(principalInput());
  const { raw, credentialId } = store.mintCredential("merchant-a");
  assert.equal(store.authenticate(raw).principal.principalId, "merchant-a");
  for (const bad of [raw.toUpperCase(), ` ${raw}`, `${raw} `, raw.slice(0, -1), `${raw}0`, `pvmk_${raw.slice(8)}`, raw.slice(8), "", null, undefined, 42, `Bearer ${raw}`]) {
    assert.equal(store.authenticate(bad), null, `must refuse ${JSON.stringify(bad)}`);
  }
  // a second, unrelated principal's key never authenticates as merchant-a
  store.createPrincipal(principalInput({ principalId: "merchant-b", allowedPayTo: { mode: "any" } }));
  const other = store.mintCredential("merchant-b");
  assert.equal(store.authenticate(other.raw).principal.principalId, "merchant-b");
  // revoke → immediate
  store.revokeCredential("merchant-a", credentialId);
  assert.equal(store.authenticate(raw), null);
  assert.equal(store.authenticate(other.raw).principal.principalId, "merchant-b");
  // expiry
  const expiring = store.mintCredential("merchant-b", { allowOverlap: true, expiresAt: new Date(Date.now() + 1000).toISOString() });
  assert.ok(store.authenticate(expiring.raw));
  assert.equal(store.authenticate(expiring.raw, Date.now() + 2000), null);
  // principal revocation kills every credential
  store.revokePrincipal("merchant-b");
  assert.equal(store.authenticate(other.raw), null);
  assert.equal(store.authenticate(expiring.raw), null);
});

test("principals: rotation needs explicit overlap; rotation never changes the principal identity or its constraints", () => {
  const store = new PrincipalStore({ dir: tmp("x402f-principals-") });
  const created = store.createPrincipal(principalInput());
  const first = store.mintCredential("merchant-a");
  assert.throws(() => store.mintCredential("merchant-a"), /allowOverlap/);
  const second = store.mintCredential("merchant-a", { allowOverlap: true, label: "rotated" });
  const p1 = store.authenticate(first.raw);
  const p2 = store.authenticate(second.raw);
  assert.equal(p1.principal.principalId, p2.principal.principalId);
  assert.deepEqual(p2.principal.allowedPayTo, created.allowedPayTo);
  store.revokeCredential("merchant-a", first.credentialId);
  assert.equal(store.authenticate(first.raw), null);
  assert.ok(store.authenticate(second.raw));
});

test("principals: closed schema — unknown fields, unknown operations/networks, implicit payTo mode, raw credential in a record all fail closed; a malformed file disables only that principal", () => {
  const dir = tmp("x402f-principals-");
  const store = new PrincipalStore({ dir });
  assert.throws(() => store.createPrincipal(principalInput({ operations: ["verify", "admin"] })), /operations/);
  assert.throws(() => store.createPrincipal(principalInput({ networks: ["kaspa:testnet-11"] })), /network/);
  assert.throws(() => store.createPrincipal(principalInput({ networks: [] })), /network/);
  assert.throws(() => store.createPrincipal(principalInput({ allowedPayTo: {} })), /mode/);
  assert.throws(() => store.createPrincipal(principalInput({ allowedPayTo: { mode: "list", addresses: [] } })), /non-empty/);
  assert.throws(() => store.createPrincipal(principalInput({ allowedResourceOrigins: { mode: "list", origins: ["https://a.example/path"] } })), /bare origin/);
  assert.throws(() => store.createPrincipal(principalInput({ principalId: "Bad_Id" })), /principalId/);
  const good = store.createPrincipal(principalInput());
  assert.throws(() => normalizePrincipal({ ...good, extra: 1 }), /unknown field/);
  assert.throws(() => normalizePrincipal({ ...good, credentials: [{ credentialId: "0d5a9b2e-3c4f-4a1b-9c8d-7e6f5a4b3c2d", label: "", verifier: `pvx402f_${"0".repeat(64)}`.slice(0, 64), status: "active", createdAt: good.createdAt, expiresAt: null, revokedAt: null }] }), /sha256|raw credential/);
  fs.writeFileSync(path.join(dir, "broken.json"), "{not json");
  const { raw } = store.mintCredential("merchant-a");
  assert.ok(store.authenticate(raw), "a malformed sibling file must not break authentication of valid principals");
  assert.equal(store.list().length, 1);
});
