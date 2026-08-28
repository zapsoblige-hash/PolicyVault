"use strict";

/*
 * AUDIT HASH CHAIN — JSON backend + real api.handle flows (fullscale
 * surface 17 residual; docs/postlaunch/audit-chain-spec.md;
 * server/src/audit-chain.js, audit.js wiring, migration 008 shape is the
 * PG suite's subject).
 *
 * Real server api.handle() on the JSON backend, hosted authMode (the
 * webhooks/events harness pattern): a real v0.4 vault for wallet A;
 * wallet B a signed-in FOREIGN tenant; machine credentials for scope
 * gating.
 *
 * Proves: the chain builds across REAL flows (a real ownerPause build's
 * GOVERNANCE_REDUCTION line, agent-suspension + org-controls metadata,
 * notification-rule audit) with contiguous seqs from the deterministic
 * genesis anchor; recordHash recomputes from the SDK PUBLIC ENTRY's
 * canonicalJsonStringify (G-2 identity asserted); sdk-internal audit
 * writes (org creation) are counted UNCHAINED and never claimed chained;
 * tamper of ANY persisted content byte -> BROKEN RECORD_TAMPERED at the
 * right seq; interior deletion -> SEQ_GAP; prevHash flip -> LINK_BROKEN;
 * recordHash flip -> RECORD_TAMPERED; tail truncation vs the durable
 * anchor -> TAIL_TRUNCATED; bounded walks continue via nextFromSeq;
 * verification endpoint gating (401 / 403 SCOPE_FORBIDDEN / foreign
 * tenant verifies STRUCTURE ONLY — no record content in the response);
 * head-anchor loss recovery from records; fail-safe `chain` field
 * collision handling.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const chainMod = require("../../server/src/audit-chain");
const sdkEntry = require("../src/index");
const { canonicalJsonStringify } = require("../src/canonical-json");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-auditchain-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0xa1); // vault owner
const B = KEY(0xb2); // foreign, signed-in tenant, no vault
const AGENT = KEY(0xc3);
const AGENT2 = KEY(0xc5); // removable second agent (REDUCTION flow)
const RECIP = KEY(0xd4);
const VAULT_ID = "6c".repeat(32);
const AUDIT_FILE = path.join(dataRoot, "audit", "events.log");

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
  return v.headers["Set-Cookie"].split(";")[0];
}

async function seedVault() {
  const template = { owner: XO(A), vaultId: VAULT_ID };
  const agentEntry = (pk) => ({
    agentPk: XO(pk), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(RECIP)]
  });
  const registry = [agentEntry(AGENT), agentEntry(AGENT2)];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "audit chain test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "81".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "43".repeat(32) },
    creationTxId: "82".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const ownerFuel = () => ({ outpoint: { transactionId: "83".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(A)}ac` });

/* Raw chained records from the JSONL, in append order. */
function chainedRecords() {
  return fs
    .readFileSync(AUDIT_FILE, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .filter((r) => r.chain !== undefined);
}

/* Rewrite the audit JSONL through an editor over parsed lines. */
function editAuditFile(fn) {
  const lines = fs.readFileSync(AUDIT_FILE, "utf8").trim().split("\n").filter(Boolean);
  const next = fn(lines);
  fs.writeFileSync(AUDIT_FILE, next.join("\n") + "\n");
}

const state = {};

test("setup: seed vault; A and B sign in; machine credentials minted (read:audit vs no-audit-scope)", async () => {
  fs.writeFileSync(path.join(dataRoot, ".pv-network"), config.networkId);
  await seedVault();
  state.cookieA = await signIn(A);
  state.cookieB = await signIn(B);
  const auditCred = await POST(["identities"], { label: "audit-reader", scopes: ["read:audit"] }, state.cookieA);
  assert.equal(auditCred.status, 201);
  state.tokenAudit = auditCred.body.credential.token;
  const buildOnly = await POST(["identities"], { label: "build-only", scopes: ["request:build", "request:break-glass"] }, state.cookieA);
  state.tokenBuildOnly = buildOnly.body.credential.token;
});

test("CHAIN BUILDS across real flows: removeAgent build (governed REDUCTION), agent suspension + notification-rule metadata — contiguous seqs from the deterministic genesis anchor", async () => {
  // Real request flow: removeAgent classifies as an authority REDUCTION
  // (governed, lighter lane) and writes a chained governance audit line
  // at build time.
  const built = await POST(
    ["wallet", "v4", "requests"],
    { vaultId: VAULT_ID, action: "removeAgent", params: { fuel: ownerFuel(), agentPk: XO(AGENT2) }, signerAddress: ADDR(A) },
    state.cookieA
  );
  assert.equal(built.status, 201);
  // Hosted-layer metadata flows (api.js appendAudit).
  const susp = await POST(["vaults", VAULT_ID, "agent-suspensions"], { op: "suspend", allAgents: true }, state.cookieA);
  assert.equal(susp.status, 200);
  const unsusp = await POST(["vaults", VAULT_ID, "agent-suspensions"], { op: "unsuspend", allAgents: true }, state.cookieA);
  assert.equal(unsusp.status, 200);
  // Notification-rule mutation (notifications.js appendAudit).
  const rule = await POST(["notifications", "rules"], { label: "chain-suite", channel: { type: "console" } }, state.cookieA);
  assert.equal(rule.status, 201);
  state.ruleId = rule.body.rule.ruleId;

  const records = chainedRecords();
  assert.ok(records.length >= 4, `at least 4 chained records (got ${records.length})`);
  const kinds = new Set(records.map((r) => r.kind));
  assert.ok(kinds.has("governance"), "real request flow contributed a governance record");
  assert.ok(kinds.has("metadata"), "suspension metadata chained");
  assert.ok(kinds.has("notification"), "notification-rule audit chained");
  records.forEach((r, i) => assert.equal(r.chain.seq, i + 1, "contiguous seqs in append order"));
  assert.equal(records[0].chain.prevHash, chainMod.genesisAnchor(config.networkId), "seq 1 links to the deterministic genesis anchor");
  for (let i = 1; i < records.length; i++) {
    assert.equal(records[i].chain.prevHash, records[i - 1].chain.recordHash, "each prevHash is the prior recordHash");
  }
  state.chainedCount = records.length;

  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.status, 200);
  assert.equal(v.body.status, "VALID");
  assert.equal(v.body.complete, true);
  assert.equal(v.body.checked.count, records.length);
  assert.equal(v.body.head.seq, records.length);
});

test("G-2 RULE: recordHash recomputes via the SDK PUBLIC ENTRY canonicalJsonStringify (same module object; key order irrelevant)", async () => {
  assert.equal(sdkEntry.canonicalJsonStringify, canonicalJsonStringify, "the public entry re-exports the exact G-2 serializer the chain uses");
  const record = chainedRecords()[0];
  const { chain, ...content } = record;
  const preimage = sdkEntry.canonicalJsonStringify({ content, nonce: chain.nonce, prevHash: chain.prevHash, seq: chain.seq });
  const recomputed = crypto.createHash("sha256").update(preimage, "utf8").digest("hex");
  assert.equal(recomputed, chain.recordHash, "independent recomputation from the public entry matches");
  // Key order of the content must be irrelevant (the jsonb reorder class).
  const reordered = {};
  for (const k of Object.keys(content).sort().reverse()) reordered[k] = content[k];
  const recomputed2 = crypto
    .createHash("sha256")
    .update(sdkEntry.canonicalJsonStringify({ content: reordered, nonce: chain.nonce, prevHash: chain.prevHash, seq: chain.seq }), "utf8")
    .digest("hex");
  assert.equal(recomputed2, chain.recordHash, "reordered keys hash identically");
});

test("UNCHAINED COMPAT: an sdk-internal audit write (org creation) is counted unchained, never claimed chained; the chained subsequence stays VALID", async () => {
  const org = await POST(["organizations"], { name: "chain compat org" }, state.cookieA);
  assert.equal(org.status, 201);
  state.orgId = org.body.organization.orgId;
  // org_created was written by sdk/src/organization.js -> UNCHAINED.
  const status = await GET(["audit", "chain"], {}, state.cookieA);
  assert.equal(status.status, 200);
  assert.ok(status.body.records.unchained >= 1, "sdk-internal write counted unchained");
  assert.ok(status.body.notice.includes("never claimed chained") || status.body.notice.includes("unchained"), "honest notice present");
  // org-controls update flows through the SERVER module -> CHAINED.
  const controls = await POST(["organizations", state.orgId, "controls"], { expectedVersion: 0 }, state.cookieA);
  assert.equal(controls.status, 200);
  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "VALID");
  state.chainedCount = v.body.checked.count;
  assert.equal(v.body.head.seq, state.chainedCount);
});

test("TAMPER DETECTION: flipping one persisted content byte -> RECORD_TAMPERED at the right seq; restore -> VALID again", async () => {
  const target = chainedRecords()[2]; // seq 3
  const before = fs.readFileSync(AUDIT_FILE, "utf8");
  editAuditFile((lines) =>
    lines.map((l) => {
      const r = JSON.parse(l);
      if (r.chain && r.chain.seq === 3) {
        // flip one byte inside a stored content field
        const field = r.detail !== undefined ? "detail" : "action";
        r[field] = `${String(r[field]).slice(0, -1)}~`;
        return JSON.stringify(r);
      }
      return l;
    })
  );
  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "BROKEN");
  assert.deepEqual(v.body.broken, { atSeq: 3, reason: "RECORD_TAMPERED" });
  fs.writeFileSync(AUDIT_FILE, before);
  const ok = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(ok.body.status, "VALID");
  assert.equal(target.chain.seq, 3);
});

test("TAMPER DETECTION: interior deletion -> SEQ_GAP; prevHash flip -> LINK_BROKEN; recordHash flip -> RECORD_TAMPERED", async () => {
  const before = fs.readFileSync(AUDIT_FILE, "utf8");
  // interior deletion (remove seq 2)
  editAuditFile((lines) => lines.filter((l) => !(JSON.parse(l).chain?.seq === 2)));
  let v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "BROKEN");
  assert.deepEqual(v.body.broken, { atSeq: 2, reason: "SEQ_GAP" });
  fs.writeFileSync(AUDIT_FILE, before);
  // prevHash flip on seq 4
  editAuditFile((lines) =>
    lines.map((l) => {
      const r = JSON.parse(l);
      if (r.chain?.seq === 4) {
        r.chain.prevHash = r.chain.prevHash.replace(/^./, r.chain.prevHash[0] === "0" ? "1" : "0");
        return JSON.stringify(r);
      }
      return l;
    })
  );
  v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "BROKEN");
  assert.deepEqual(v.body.broken, { atSeq: 4, reason: "LINK_BROKEN" });
  fs.writeFileSync(AUDIT_FILE, before);
  // recordHash flip on seq 1
  editAuditFile((lines) =>
    lines.map((l) => {
      const r = JSON.parse(l);
      if (r.chain?.seq === 1) {
        r.chain.recordHash = r.chain.recordHash.replace(/^./, r.chain.recordHash[0] === "0" ? "1" : "0");
        return JSON.stringify(r);
      }
      return l;
    })
  );
  v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "BROKEN");
  assert.deepEqual(v.body.broken, { atSeq: 1, reason: "RECORD_TAMPERED" });
  fs.writeFileSync(AUDIT_FILE, before);
});

test("TAIL TRUNCATION: cutting the newest chained records is caught by the durable anchor (TAIL_TRUNCATED); restore -> VALID", async () => {
  const before = fs.readFileSync(AUDIT_FILE, "utf8");
  const head = (await GET(["audit", "chain"], {}, state.cookieA)).body.head;
  editAuditFile((lines) => lines.filter((l) => (JSON.parse(l).chain?.seq ?? 0) < head.seq));
  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "BROKEN");
  assert.equal(v.body.broken.reason, "TAIL_TRUNCATED");
  assert.equal(v.body.broken.atSeq, head.seq);
  fs.writeFileSync(AUDIT_FILE, before);
  assert.equal((await GET(["audit", "chain", "verify"], {}, state.cookieA)).body.status, "VALID");
});

test("BOUNDED WALKS: limit=2 -> complete:false + nextFromSeq continuation covers the whole chain; window past the head is VALID-empty; bad params 400", async () => {
  let from = 1;
  let total = 0;
  for (let i = 0; i < 20; i++) {
    const v = await GET(["audit", "chain", "verify"], { fromSeq: String(from), limit: "2" }, state.cookieA);
    assert.equal(v.body.status, "VALID");
    total += v.body.checked.count;
    if (v.body.complete) break;
    assert.ok(v.body.nextFromSeq > from);
    from = v.body.nextFromSeq;
  }
  assert.equal(total, state.chainedCount, "continuation covered every chained record");
  const past = await GET(["audit", "chain", "verify"], { fromSeq: String(state.chainedCount + 10) }, state.cookieA);
  assert.equal(past.body.status, "VALID");
  assert.equal(past.body.checked.count, 0);
  await expectThrow(GET(["audit", "chain", "verify"], { fromSeq: "zero" }, state.cookieA), 400, "AUDIT_CHAIN_BAD_RANGE");
  await expectThrow(GET(["audit", "chain", "verify"], { fromSeq: "5", toSeq: "2" }, state.cookieA), 400, "AUDIT_CHAIN_BAD_RANGE");
});

test("GATING: hosted requires auth (401); machine credential without read:audit -> 403 SCOPE_FORBIDDEN; with read:audit -> 200; foreign tenant verifies STRUCTURE ONLY", async () => {
  await expectThrow(GET(["audit", "chain", "verify"], {}, undefined), 401, "SESSION_INVALID");
  await expectThrow(GET(["audit", "chain"], {}, { authorization: `Bearer ${state.tokenBuildOnly}` }), 403, "SCOPE_FORBIDDEN");
  const viaMachine = await GET(["audit", "chain", "verify"], {}, { authorization: `Bearer ${state.tokenAudit}` });
  assert.equal(viaMachine.status, 200);
  assert.equal(viaMachine.body.status, "VALID");
  // Foreign tenant B may confirm integrity of the shared stream...
  const viaB = await GET(["audit", "chain", "verify"], {}, state.cookieB);
  assert.equal(viaB.status, 200);
  assert.equal(viaB.body.status, "VALID");
  // ...but the response carries NO record content: none of the detail
  // strings, kinds, actions, or ids of A's audit records appear.
  const raw = JSON.stringify(viaB.body);
  for (const needle of ["GOVERNANCE_REDUCTION", "agent_suspension_updated", "notification_rule_created", "chain-suite", VAULT_ID, state.ruleId, "removeAgent"]) {
    assert.ok(!raw.includes(needle), `verification response must not leak record content (${needle})`);
  }
  // The tenant-scoped audit feed still refuses B the content itself.
  const feedB = await GET(["audit"], {}, state.cookieB);
  assert.equal(feedB.body.events.length, 0, "B sees no foreign audit records via the feed");
});

test("HEAD-ANCHOR LOSS: deleting the durable anchor is recovered from the records; appends continue the same chain", async () => {
  const anchorDir = path.join(dataRoot, "platform", "audit-chain");
  const before = (await GET(["audit", "chain"], {}, state.cookieA)).body.head;
  for (const f of fs.readdirSync(anchorDir)) fs.unlinkSync(path.join(anchorDir, f));
  chainMod.resetProcessCache(); // simulate a fresh process
  // A new chained append recovers the head from the records.
  const rule = await POST(["notifications", "rules"], { label: "post-anchor-loss", channel: { type: "console" } }, state.cookieA);
  assert.equal(rule.status, 201);
  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "VALID");
  assert.equal(v.body.head.seq, before.seq + 1, "chain continued from the records, not from genesis");
  state.chainedCount = v.body.checked.count;
  state.lossRuleId = rule.body.rule.ruleId;
});

test("FAIL-SAFE COLLISION: an event already carrying a `chain` field is preserved under chainFieldCollision and chained normally — verification stays VALID", async () => {
  const { appendAudit } = require("../../server/src/audit");
  const record = await appendAudit(config, { kind: "metadata", action: "collision_probe", result: "OK", chain: "caller-junk" });
  assert.equal(record.chainFieldCollision, "caller-junk");
  assert.equal(record.chain.v, chainMod.CHAIN_SCHEMA);
  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "VALID");
  state.chainedCount = v.body.checked.count;
});

test("BIGINT/STORAGE-NORMAL: a record carrying BigInt values chains over its storage-normal form and re-verifies from disk", async () => {
  const { appendAudit } = require("../../server/src/audit");
  const record = await appendAudit(config, { kind: "metadata", action: "bigint_probe", result: "OK", feeSompi: 12345n });
  assert.equal(record.feeSompi, "12345", "BigInt normalized to its stored string form before hashing");
  const v = await GET(["audit", "chain", "verify"], {}, state.cookieA);
  assert.equal(v.body.status, "VALID");
});

test("cleanup: remove temp data root", async () => {
  fs.rmSync(dataRoot, { recursive: true, force: true });
});
