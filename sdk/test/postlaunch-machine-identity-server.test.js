"use strict";

/*
 * MACHINE (AI/AGENT) IDENTITIES + SCOPED CAPABILITIES
 * (completion-standard surface 6; docs/postlaunch/platform-agent-api-spec.md;
 * server/src/machine-identity.js + server/src/scopes.js).
 *
 * Real server api.handle() (JSON backend, hosted authMode — no PostgreSQL
 * required for this file: hosted authentication does not require the
 * postgres persistence backend, only tenancyEnforced/authMode=enabled;
 * verified directly against sdk/src/config.js). A real v0.4 vault is
 * seeded for wallet A; wallet B is a signed-in FOREIGN tenant.
 *
 * Proves: token minted once, hashed at rest, never recoverable from
 * storage; a machine principal inherits EXACTLY its creating wallet's
 * tenancy (never more); deny-by-default scope enforcement (missing scope
 * -> refused BEFORE the underlying pipeline runs — no durable request
 * created); the break-glass scope carve-out; machine-identity management
 * itself is wallet-session-only (never reachable by a machine credential,
 * even one holding no restrictive scope at all); cross-tenant isolation
 * (B cannot see/mint/revoke A's identities); credential rotation/
 * revocation semantics; self-hosted mode has no machine-identity surface
 * at all.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-machineid-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0xa1); // vault owner
const B = KEY(0xb2); // foreign, signed-in tenant, no vault
const AGENT = KEY(0xc3);
const RECIP = KEY(0xd4);
const VAULT_ID = "9a".repeat(32);

const POST = (segs, body, cookieOrHeaders) => handle(config, "POST", segs, {}, body, ctxFor(cookieOrHeaders));
const GET = (segs, query, cookieOrHeaders) => handle(config, "GET", segs, query ?? {}, null, ctxFor(cookieOrHeaders));
function ctxFor(cookieOrHeaders) {
  if (!cookieOrHeaders) return {};
  if (typeof cookieOrHeaders === "string") return { headers: { cookie: cookieOrHeaders } };
  return { headers: cookieOrHeaders };
}
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

async function signIn(priv) {
  const address = ADDR(priv);
  const ch = await POST(["auth", "challenge"], { walletAddress: address });
  const signature = kaspa.signMessage({ message: ch.body.challenge.message, privateKey: priv.toString() });
  const v = await POST(["auth", "verify"], { nonce: ch.body.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() });
  const setCookie = v.headers["Set-Cookie"];
  return setCookie.split(";")[0]; // "pv_session=<token>"
}

async function seedVault() {
  const template = { owner: XO(A), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
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
    label: "machine-identity test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "77".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "78".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const ownerFuel = () => ({ outpoint: { transactionId: "79".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(A)}ac` });

function allPlatformFileContents() {
  const root = path.join(dataRoot, "platform");
  if (!fs.existsSync(root)) return "";
  let out = "";
  for (const dir of fs.readdirSync(root)) {
    const d = path.join(root, dir);
    if (!fs.statSync(d).isDirectory()) continue;
    for (const f of fs.readdirSync(d)) out += fs.readFileSync(path.join(d, f), "utf8");
  }
  return out;
}

const state = {};

test("setup: seed vault; A and B sign in", async () => {
  await seedVault();
  state.cookieA = await signIn(A);
  state.cookieB = await signIn(B);
});

test("identity + credential creation: token shown once, pvmk_ prefixed, never stored in plaintext anywhere on disk", async () => {
  const r = await POST(["identities"], { label: "ci-agent", scopes: ["read:vaults", "request:build"] }, state.cookieA);
  assert.equal(r.status, 201);
  assert.match(r.body.credential.token, /^pvmk_[0-9a-f]{64}$/);
  assert.equal(r.body.identity.creatorXOnly, XO(A));
  assert.deepEqual(r.body.identity.scopes, ["read:vaults", "request:build"]);
  assert.equal(r.body.identity.status, "ACTIVE");
  state.identityA1 = r.body.identity;
  state.tokenA1 = r.body.credential.token;
  state.credentialA1 = r.body.credential;

  // GET presentation never carries the token or a hash.
  const listed = await GET(["identities"], {}, state.cookieA);
  assert.equal(listed.status, 200);
  const found = listed.body.identities.find((i) => i.identityId === state.identityA1.identityId);
  assert.ok(found);
  assert.equal(JSON.stringify(found).includes(state.tokenA1), false);

  const detail = await GET(["identities", state.identityA1.identityId], {}, state.cookieA);
  assert.equal(detail.status, 200);
  assert.equal(detail.body.credentials.length, 1);
  assert.equal(detail.body.credentials[0].tokenPrefix.length < state.tokenA1.length, true);
  assert.equal(JSON.stringify(detail.body).includes(state.tokenA1), false);

  // The raw token never appears anywhere in durable storage — only its
  // SHA-256 (a 64-hex string unrelated byte-for-byte to the token itself).
  const disk = allPlatformFileContents();
  assert.equal(disk.includes(state.tokenA1), false, "raw bearer token must never be persisted");
  assert.equal(disk.includes("pvmk_" + "0".repeat(64)), false); // sanity: search actually finds content
  assert.ok(disk.length > 0, "sanity: platform files were actually written");
});

test("unknown scope at creation fails closed; empty scopes fails closed", async () => {
  await expectThrow(POST(["identities"], { scopes: ["not:a:real:scope"] }, state.cookieA), 422, "MACHINE_IDENTITY_SCOPE_UNKNOWN");
  await expectThrow(POST(["identities"], { scopes: [] }, state.cookieA), 422, "MACHINE_IDENTITY_SCOPES_REQUIRED");
  await expectThrow(POST(["identities"], {}, state.cookieA), 422, "MACHINE_IDENTITY_SCOPES_REQUIRED");
});

test("a resolved machine principal inherits EXACTLY its creator's tenancy (A's vault, never more)", async () => {
  const r = await GET(["vaults"], {}, { authorization: `Bearer ${state.tokenA1}` });
  assert.equal(r.status, 200);
  assert.equal(r.body.vaults.length, 1);
  assert.equal(r.body.vaults[0].vaultId, VAULT_ID);
});

test("scope escalation attempts are refused BEFORE the pipeline runs — no durable request is created", async () => {
  // state.identityA1 holds read:vaults + request:build only.
  const before = fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")).length : 0;
  const e = await expectThrow(
    POST(["wallet", "v4", "requests", "some-request-id", "submit"], {}, { authorization: `Bearer ${state.tokenA1}` }),
    403,
    "SCOPE_FORBIDDEN"
  );
  assert.match(e.message, /request:submit/);
  const after = fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")).length : 0;
  assert.equal(after, before, "a scope refusal must be pure — no durable request touched");

  // organizations:manage is not held either.
  await expectThrow(POST(["organizations"], { name: "x" }, { authorization: `Bearer ${state.tokenA1}` }), 403, "SCOPE_FORBIDDEN");

  // an unmapped/garbage route is deny-by-default (403, never a 404 leak).
  await expectThrow(POST(["totally", "unknown", "route"], {}, { authorization: `Bearer ${state.tokenA1}` }), 403, "SCOPE_FORBIDDEN");
});

test("break-glass carve-out: request:build alone cannot attempt ownerPause; request:break-glass is additionally required", async () => {
  const buildOnly = await POST(["identities"], { scopes: ["request:build"] }, state.cookieA);
  const buildOnlyAuth = { authorization: `Bearer ${buildOnly.body.credential.token}` };
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(A) }, buildOnlyAuth),
    403,
    "SCOPE_FORBIDDEN"
  );
  assert.match(e.message, /request:break-glass/);

  const withBreakGlass = await POST(["identities"], { scopes: ["request:build", "request:break-glass"] }, state.cookieA);
  const bgAuth = { authorization: `Bearer ${withBreakGlass.body.credential.token}` };
  const built = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(A) }, bgAuth);
  assert.equal(built.status, 201, JSON.stringify(built.body));

  // an ORDINARY (never break-glass) action needs only request:build —
  // agentSpend, signed by the agent itself, well within its policy.
  const buildOnly2 = await POST(["identities"], { scopes: ["request:build"] }, state.cookieA);
  const ordinary = await POST(
    ["wallet", "v4", "requests"],
    { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (2n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) },
    { authorization: `Bearer ${buildOnly2.body.credential.token}` }
  );
  assert.equal(ordinary.status, 201, JSON.stringify(ordinary.body));
});

test("machine-identity management is wallet-session-only — a machine credential is refused on /identities* even with no restrictive scope needed, and on the dev-signer routes", async () => {
  await expectThrow(GET(["identities"], {}, { authorization: `Bearer ${state.tokenA1}` }), 403, "MACHINE_IDENTITY_ROUTE_FORBIDDEN");
  await expectThrow(
    POST(["identities", state.identityA1.identityId, "revoke"], {}, { authorization: `Bearer ${state.tokenA1}` }),
    403,
    "MACHINE_IDENTITY_ROUTE_FORBIDDEN"
  );

  const prior = process.env.POLICYVAULT_DEV_SIGNER;
  process.env.POLICYVAULT_DEV_SIGNER = "1";
  try {
    // Prove the machine-identity gate itself refuses this — not merely
    // riding on devSignerEnabled being false (it is now forcibly true).
    await expectThrow(GET(["wallet", "dev-accounts"], {}, { authorization: `Bearer ${state.tokenA1}` }), 403, "MACHINE_IDENTITY_ROUTE_FORBIDDEN");
    // A real wallet session (or self-hosted) is unaffected by this gate.
    const asWallet = await GET(["wallet", "dev-accounts"], {}, state.cookieA);
    assert.equal(asWallet.status, 200);
  } finally {
    if (prior === undefined) delete process.env.POLICYVAULT_DEV_SIGNER;
    else process.env.POLICYVAULT_DEV_SIGNER = prior;
  }
});

test("an invalid/garbage/revoked machine credential is refused (401), never silently anonymous", async () => {
  await expectThrow(GET(["vaults"], {}, { authorization: "Bearer not-a-real-token" }), 401, "MACHINE_TOKEN_INVALID");
  await expectThrow(GET(["vaults"], {}, { authorization: "Bearer pvmk_" + "0".repeat(64) }), 401, "MACHINE_TOKEN_INVALID");
  await expectThrow(GET(["vaults"], {}, { authorization: "not-even-bearer-shaped" }), 401, "MACHINE_TOKEN_INVALID");
});

test("cross-tenant isolation: B (a real signed-in wallet with no identities) cannot see, mint for, or revoke A's identity", async () => {
  const listedByB = await GET(["identities"], {}, state.cookieB);
  assert.equal(listedByB.status, 200);
  assert.equal(listedByB.body.identities.length, 0);

  await expectThrow(GET(["identities", state.identityA1.identityId], {}, state.cookieB), 404, "MACHINE_IDENTITY_NOT_FOUND");
  await expectThrow(POST(["identities", state.identityA1.identityId, "credentials"], {}, state.cookieB), 404, "MACHINE_IDENTITY_NOT_FOUND");
  await expectThrow(POST(["identities", state.identityA1.identityId, "revoke"], {}, state.cookieB), 404, "MACHINE_IDENTITY_NOT_FOUND");
  await expectThrow(
    POST(["identities", state.identityA1.identityId, "credentials", state.credentialA1.credentialId, "revoke"], {}, state.cookieB),
    404,
    "MACHINE_IDENTITY_NOT_FOUND"
  );

  // B's OWN machine identity (if any) never sees A's vault either — proven
  // structurally already by tenancy.js; a quick end-to-end confirmation:
  const bIdentity = await POST(["identities"], { scopes: ["read:vaults"] }, state.cookieB);
  const bVaults = await GET(["vaults"], {}, { authorization: `Bearer ${bIdentity.body.credential.token}` });
  assert.equal(bVaults.body.vaults.length, 0);
});

test("credential rotation + revocation: siblings are independent; revoking the identity invalidates every credential immediately", async () => {
  const identity = await POST(["identities"], { scopes: ["read:vaults"] }, state.cookieA);
  const id = identity.body.identity.identityId;
  const cred1 = identity.body.credential.token;
  const minted2 = await POST(["identities", id, "credentials"], { label: "rotated" }, state.cookieA);
  const cred2 = minted2.body.credential.token;

  // Both work.
  assert.equal((await GET(["vaults"], {}, { authorization: `Bearer ${cred1}` })).status, 200);
  assert.equal((await GET(["vaults"], {}, { authorization: `Bearer ${cred2}` })).status, 200);

  // Revoke credential 1 only — credential 2 is unaffected.
  const revoked1 = await POST(["identities", id, "credentials", identity.body.credential.credentialId, "revoke"], {}, state.cookieA);
  assert.equal(revoked1.body.credential.status, "REVOKED");
  await expectThrow(GET(["vaults"], {}, { authorization: `Bearer ${cred1}` }), 401, "MACHINE_TOKEN_INVALID");
  assert.equal((await GET(["vaults"], {}, { authorization: `Bearer ${cred2}` })).status, 200);

  // Revoke the IDENTITY — credential 2 (never individually revoked) is
  // now ALSO refused immediately (no fan-out write needed for correctness).
  const revokedIdentity = await POST(["identities", id, "revoke"], {}, state.cookieA);
  assert.equal(revokedIdentity.body.identity.status, "REVOKED");
  await expectThrow(GET(["vaults"], {}, { authorization: `Bearer ${cred2}` }), 401, "MACHINE_TOKEN_INVALID");
  // idempotent
  const again = await POST(["identities", id, "revoke"], {}, state.cookieA);
  assert.equal(again.body.identity.status, "REVOKED");
});

test("identities routes are excluded from idempotency persistence — one-time tokens never land in idempotency_records", async () => {
  // Hazard flagged by the W2-events review: idempotency records persist
  // responses VERBATIM, and /identities create + credential mint return
  // the one-time plaintext bearer token. The route must therefore be a
  // secret-bearing exclusion (like /webhooks): no replay dedup, and no
  // token at rest anywhere in the durable store.
  const key = "identities-idem-key-1";
  const mk = () => POST(["identities"], { label: "idem-exclusion-probe", scopes: ["read:vaults"] }, { cookie: state.cookieA, idempotencyKey: key });
  const r1 = await mk();
  assert.equal(r1.status, 201);
  const token1 = r1.body.credential.token;
  assert.match(token1, /^pvmk_/);
  // No replay semantics: the SAME key mints a SECOND, distinct identity
  // (nuisance-by-design, revocable) instead of replaying the stored
  // response — proving the route never entered withIdempotency.
  const r2 = await mk();
  assert.equal(r2.status, 201);
  assert.notEqual(r2.body.identity.identityId, r1.body.identity.identityId);
  assert.notEqual(r2.body.credential.token, token1);
  assert.equal(r2.body.replayedIdempotency, undefined);
  // Secret-at-rest sweep: neither plaintext token appears ANYWHERE in the
  // durable data root (hash-at-rest everywhere, idempotency included).
  const seen = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.isFile()) seen.push(fs.readFileSync(p, "utf8"));
    }
  })(dataRoot);
  const blob = seen.join("\n");
  assert.ok(!blob.includes(token1), "plaintext token 1 found at rest");
  assert.ok(!blob.includes(r2.body.credential.token), "plaintext token 2 found at rest");
});

test("self-hosted mode (authMode disabled) has no machine-identity surface at all", async () => {
  const selfHosted = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-machineid-sh-")) });
  await expectThrow(handle(selfHosted, "POST", ["identities"], {}, { scopes: ["read:vaults"] }, {}), 404, "AUTH_DISABLED");
  // An Authorization header is silently ignored (never resolved, never
  // errors) in self-hosted mode — machine identities simply do not exist
  // there, exactly like hosted sessions do not.
  const r = await handle(selfHosted, "GET", ["vaults"], {}, null, { headers: { authorization: "Bearer pvmk_" + "1".repeat(64) } });
  assert.equal(r.status, 200);
});
