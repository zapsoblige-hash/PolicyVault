"use strict";
/*
 * RC45 R2-06 — the closed codes of the delegate period-start refusals over the
 * real hosted routes and the MCP adapter. Internal RED-first regression
 * material for the RC45 candidate; not an audit.
 *
 * THE DEFECT (b89f0f7): no route knows PERIOD_START_STALE. The v4 routes
 * answer every code outside their small state list with 422, and the
 * organizational-root routes answer every code without a STATUS_BY_CODE row
 * with 422, so "this request waited too long" (a request left exactly as it
 * was, in conflict with its lifecycle) would reach a client as a validation
 * failure of its own body.
 *
 * REQUIRED BEHAVIOUR:
 *   - PERIOD_START_STALE (new) is a 409 on every v4 check-point route (build,
 *     finalize, submit, genesis-submit: server/src/api.js v4Error state codes)
 *     and on every organizational-root / v7 route (an explicit STATUS_BY_CODE
 *     row), with the code and the server's message passed through (and, on the
 *     v4 routes, the refusal's extra fields: delegate, start, current DAA,
 *     period, window);
 *   - PERIOD_START_REQUIRED (existing) stays 422 on those routes, with an
 *     explicit STATUS_BY_CODE row; REGISTRY_ROOT_MISMATCH and VAULT_NOT_FOUND keep
 *     their existing statuses (422, 404) and CANNOT_REJECT stays 409;
 *   - the MCP adapter passes either refusal through verbatim under `data`
 *     (status REFUSED, the HTTP status, the server's code and message).
 *
 * Layers: UNIT (org-roots mapError and its closed STATUS_BY_CODE table) and API
 * (the real server/src/api.js handle in hosted mode, owner wallet sessions
 * signed in with TEST keys; the real HTTP server and the real MCP adapter
 * session with an owner-minted machine credential), over the JSON store and a
 * fresh PostgreSQL database per leg. The status-mapping legs make the route's
 * SDK call (the module export the route calls at request time) throw the
 * coded refusal the period-start rule throws, so the mapping is measured on
 * every route independently of where the rule sits; the MCP node-down legs use
 * the real builders with the node DAA read answering a thrower (the test
 * seam useAnchorDaa). Real compiler and encoder for every request a leg builds. Realistic
 * DAA values (about 5.45e8). Nothing dials a node; no production data.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const { K, R, KAS, D, DAY, said, nodeDown, withAnchor } = KK;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = KK.kasSuite("r2-06");
const V4 = Object.freeze(K.vault("r2-06-v4"));
let w = null, T = null, A = null, B = null;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup(async (template, node) => {
    w = KK.kasWallets(template);
    A = KK.kasDelegate(w.agentA.xonly, [w.recipient.xonly], { periodStartDaa: (D - 5n * DAY).toString(), periodSpent: (3n * KAS).toString() });
    B = KK.kasDelegate(w.agentB.xonly, [w.recipient.xonly], { periodStartDaa: (D - 1000n).toString() });
    T = await KK.buildRootAndTreasury(template, w, node, { label: "RC45 R2-06 TEST", agents: [A, B], kasVaultId: K.hex("rc45-r2-06-treasury") });
    // A v0.4.1 vault owned by o1 (the hosted v4 routes and the MCP v4 build).
    await R.seedVault(template, V4, { owner: w.o1 }, [V4_AGENT()], { label: "RC45 R2-06 TEST" });
  });
});
after(async () => { await S.teardown(); });

const V4_AGENT = () => R.delegate(w.agentA.xonly, [w.recipient.xonly], { periodStartDaa: (D - 1000n).toString() }); // the v4 vault's installed delegate (10 KAS per spend)
const row = (wallet, start, over = {}) => KK.kasDelegate(wallet.xonly, [w.recipient.xonly], { periodStartDaa: String(start), ...over });
const stale = (what) => Object.assign(new Error(`manifest-v4: ${what}: delegate period start 545000000 is older than its window at 545858001 — refusing`), { code: "PERIOD_START_STALE", extra: { agentPk: "ee".repeat(32), periodStartDaa: "545000000", currentDaa: "545858001", periodLengthDaa: "864000", windowDaa: "858000" } });
const required = (what) => Object.assign(new Error(`chain: ${what}: PERIOD_START_REQUIRED: the configured node is unavailable (TEST)`), { code: "PERIOD_START_REQUIRED" });
const coded = (code, what) => Object.assign(new Error(`TEST ${what}: ${code}`), { code });
/* Make the module export a route calls at request time throw `make()`, for the duration of `fn`. */
async function throwing(mod, name, make, fn) {
  const real = mod[name];
  assert.equal(typeof real, "function", `${name} is the module export the route calls`);
  mod[name] = async () => { throw make(); };
  try { return await fn(); } finally { mod[name] = real; }
}
const v4Fuel = (tag) => ({ outpoint: { transactionId: K.hex(`rc45-r2-06-v4-fuel-${tag}`), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${w.o1.xonly}ac` });
const v4Sign = (config, request) => R.cand.signer.makeDevSigner(config, { secretHex: w.o1.secretHex, expectedAddress: w.o1.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);

/* ---------------- UNIT: the organizational-root status table ---------------- */
test("RC45 R2-06 UNIT: org-roots mapError answers a PERIOD_START_STALE refusal with 409 (the request was left unchanged; a conflict with its lifecycle, not a validation failure of the call) and keeps the code and message [RED on b89f0f7]", () => {
  const { mapError } = require("../../server/src/org-roots");
  const e = mapError(stale("root-finalize"));
  assert.equal(e.status, 409, "PERIOD_START_STALE is a 409");
  assert.equal(e.code, "PERIOD_START_STALE");
  assert.match(e.message, /older than its window/);
});

test("RC45 R2-06 UNIT: org-roots mapError keeps PERIOD_START_REQUIRED at 422, REGISTRY_ROOT_MISMATCH at 422, VAULT_NOT_FOUND at 404 and CANNOT_REJECT at 409, and passes an error that already carries a status through", () => {
  const { mapError } = require("../../server/src/org-roots");
  for (const [code, status] of [["PERIOD_START_REQUIRED", 422], ["REGISTRY_ROOT_MISMATCH", 422], ["VAULT_NOT_FOUND", 404], ["CANNOT_REJECT", 409]]) {
    const e = mapError(coded(code, "unit"));
    assert.equal(e.status, status, `${code} -> ${status}`);
    assert.equal(e.code, code);
  }
  const own = Object.assign(new Error("own"), { status: 403, code: "REQUEST_FORBIDDEN" });
  assert.equal(mapError(own), own);
});

test("RC45 R2-06 UNIT: the closed STATUS_BY_CODE table of server/src/org-roots.js carries an explicit row PERIOD_START_REQUIRED: 422 and an explicit row PERIOD_START_STALE: 409 (every closed code gets its own row) [RED on b89f0f7]", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "..", "server", "src", "org-roots.js"), "utf8");
  const m = /const STATUS_BY_CODE = Object\.freeze\((\{[\s\S]*?\n\})\);/.exec(src);
  assert.ok(m, "STATUS_BY_CODE is a frozen object literal");
  const table = vm.runInNewContext(`(${m[1]})`);
  assert.ok(Object.prototype.hasOwnProperty.call(table, "PERIOD_START_REQUIRED"), "an explicit PERIOD_START_REQUIRED row");
  assert.equal(table.PERIOD_START_REQUIRED, 422);
  assert.ok(Object.prototype.hasOwnProperty.call(table, "PERIOD_START_STALE"), "an explicit PERIOD_START_STALE row");
  assert.equal(table.PERIOD_START_STALE, 409);
});

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-06 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend, w); try { await fn(x); } finally { await S.release(x); } });

  /* A BUILT v4 ownerPause and a BUILT v4 genesis (no delegate: node-free), for the v4 check-point routes. */
  async function v4Requests(x) {
    const pause = await x.call("POST", ["wallet", "v4", "requests"], { vaultId: V4.vaultId, action: "ownerPause", params: { fuel: v4Fuel("pause") }, signerAddress: w.o1.address }, x.cookie.o1);
    assert.equal(pause.status, 201, `a v4 ownerPause is built (${said(pause)})`);
    const genesis = await x.call("POST", ["wallet", "v4", "create"], { templateInput: { owner: w.o1.xonly, vaultId: K.hex("rc45-r2-06-v4-genesis") }, initialAgents: [], initialState: { protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: w.o1.address, funding: [R.fundingFor(w.o1, "r2-06-v4-genesis")], contractVersion: "policyvault-0.4.1", label: "RC45 R2-06 TEST genesis" }, x.cookie.o1);
    assert.equal(genesis.status, 201, `a v4 genesis is built (${said(genesis)})`);
    return { pause: await R.cand.wr4.loadRequest(x.config, pause.body.request.requestId), genesis: await R.cand.wr4.loadRequest(x.config, genesis.body.request.requestId) };
  }
  /* Every v4 check-point route, with the SDK call it makes answering `make()`. */
  async function v4Routes(x, make) {
    const { pause, genesis } = await v4Requests(x);
    const wr4 = R.cand.wr4, submit4 = R.cand.submit4, out = {};
    out.build = await throwing(wr4, "buildWalletRequestV4", () => make("build"), () => x.call("POST", ["wallet", "v4", "requests"], { vaultId: V4.vaultId, action: "ownerPause", params: { fuel: v4Fuel("pause-2") }, signerAddress: w.o1.address }, x.cookie.o1));
    out.finalize = await throwing(wr4, "finalizeWalletRequestV4", () => make("finalize"), () => x.call("POST", ["wallet", "v4", "requests", pause.requestId, "signature"], { signedSafeJson: v4Sign(x.config, pause) }, x.cookie.o1));
    out.submit = await throwing(submit4, "submitWalletRequestV4", () => make("submit"), () => x.call("POST", ["wallet", "v4", "requests", pause.requestId, "submit"], {}, x.cookie.o1));
    out["genesis-submit"] = await throwing(submit4, "submitCreateWalletRequestV4", () => make("genesis-submit"), () => x.call("POST", ["wallet", "v4", "requests", genesis.requestId, "genesis-submit"], { signedSafeJson: v4Sign(x.config, genesis) }, x.cookie.o1));
    return out;
  }
  /* Every v0.7 organizational-root / KAS check-point route, with the SDK call it makes answering `make()`. */
  async function v7Routes(x, make) {
    const out = {}, wr7 = KK.lazy.wr7, wr7kas = KK.lazy.wr7kas;
    const g = await withAnchor(D, () => x.kasGenesis(T.rootId, { label: "RC45 R2-06 TEST creation", agents: [row(w.n1, D)], approvers: [], approvalM: 0, recoveryAddress: w.recovery.address, depositKas: "10", feeReserveKas: "1", signerAddress: w.o1.address, funding: [KK.p2pkUtxo(w.o1, "r2-06-creation", 200n)], vaultId: K.hex("rc45-r2-06-creation") }));
    assert.equal(g.status, 201, `a treasury creation is built (${said(g)})`);
    const r = await withAnchor(D, () => x.setAgents(T.rootId, T.vaultId, [A, B, row(w.n1, D)], { tag: "codes" }));
    assert.equal(r.status, 201, `a delegate-rule change is built (${said(r)})`);
    await x.quorum(T.rootId, r.body.request.id);
    out["treasury creation"] = await throwing(wr7kas, "buildKasVaultGenesisRequest", () => make("kas-genesis"), () => x.kasGenesis(T.rootId, { label: "RC45 R2-06 TEST creation 2", agents: [row(w.n1, D)], approvers: [], approvalM: 0, recoveryAddress: w.recovery.address, depositKas: "10", feeReserveKas: "1", signerAddress: w.o1.address, funding: [KK.p2pkUtxo(w.o1, "r2-06-creation-2", 200n)], vaultId: K.hex("rc45-r2-06-creation-2") }));
    out["creation signature"] = await throwing(wr7kas, "finalizeKasWalletRequest", () => make("kas-genesis-signature"), () => x.kasSign(g.body.request.requestId));
    out["root request build"] = await throwing(wr7, "buildRootActionRequest", () => make("kas-root-op"), () => x.rootBuild(T.rootId, { action: "authorize", params: { fuel: x.node.seedFuel(KK.p2pkUtxo(w.fee, "r2-06-build")) }, vaultOperations: [{ vaultId: T.vaultId, action: "ownerSetAgentRoot", params: { agents: [A, B, row(w.n2, D)] } }], signerAddress: w.o1.address }));
    out["root finalize"] = await throwing(wr7, "finalizeOrgRootRequest", () => make("root-finalize"), () => x.rootFinalize(T.rootId, r.body.request.id));
    return out;
  }

  /* ---------------- the v4 routes (server/src/api.js v4Error) ---------------- */
  leg("every hosted v4 check-point route (build, finalize, submit, genesis-submit) answers the rule's PERIOD_START_STALE refusal with 409, passing the code and the server's message through; build, finalize and submit (which forward the refusal's extra fields) also pass the delegate, start, current DAA, period and window through [RED on b89f0f7]", async (x) => {
    const out = await v4Routes(x, stale);
    for (const [route, r] of Object.entries(out)) {
      assert.equal(r.status, 409, `${route}: PERIOD_START_STALE is a 409 (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_STALE", `${route}: the code`);
      assert.match(r.message, /older than its window/, `${route}: the server's message`);
      if (route === "genesis-submit") continue; // this route answers with the request as its extra (unchanged)
      for (const f of ["agentPk", "periodStartDaa", "currentDaa", "periodLengthDaa", "windowDaa"]) assert.equal(r.extra && r.extra[f], stale("x").extra[f], `${route}: extra.${f} reaches the caller`);
    }
  });

  leg("every hosted v4 check-point route keeps PERIOD_START_REQUIRED at 422 with its code and message", async (x) => {
    const out = await v4Routes(x, required);
    for (const [route, r] of Object.entries(out)) {
      assert.equal(r.status, 422, `${route}: PERIOD_START_REQUIRED is a 422 (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED", `${route}: the code`);
      assert.match(r.message, /node is unavailable/, `${route}: the server's message`);
    }
  });

  /* ---------------- the v0.7 organizational-root routes (server/src/org-roots.js mapError) ---------------- */
  leg("every hosted v0.7 check-point route (treasury creation, its signature, root request build, root finalize) answers the rule's PERIOD_START_STALE refusal with 409 and passes the code and message through [RED on b89f0f7]", async (x) => {
    const out = await v7Routes(x, stale);
    for (const [route, r] of Object.entries(out)) {
      assert.equal(r.status, 409, `${route}: PERIOD_START_STALE is a 409 (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_STALE", `${route}: the code`);
      assert.match(r.message, /older than its window/, `${route}: the server's message`);
    }
  });

  leg("every hosted v0.7 check-point route keeps PERIOD_START_REQUIRED and REGISTRY_ROOT_MISMATCH at 422 with their codes", async (x) => {
    for (const [code, make] of [["PERIOD_START_REQUIRED", required], ["REGISTRY_ROOT_MISMATCH", (what) => coded("REGISTRY_ROOT_MISMATCH", what)]]) {
      const y = code === "PERIOD_START_REQUIRED" ? x : await S.fresh(backend, w);
      try {
        const out = await v7Routes(y, make);
        for (const [route, r] of Object.entries(out)) {
          assert.equal(r.status, 422, `${route}: ${code} is a 422 (${said(r)})`);
          assert.equal(r.code, code, `${route}: the code`);
        }
      } finally { if (y !== x) await S.release(y); }
    }
  });

  /* ---------------- the MCP adapter: refusals passed through verbatim ---------------- */
  async function withMcp(x, scopes, fn) {
    const token = await x.credential(scopes);
    const http = await x.http();
    const mcp = KK.mcpSession({ baseUrl: http.baseUrl, token });
    try { await mcp.start(); return await fn(mcp); } finally { mcp.close(); await http.close(); }
  }
  const refused = (res, label) => {
    const sc = res.result && res.result.structuredContent;
    assert.ok(sc, `${label}: MCP answered a tool result (${JSON.stringify(res.error ?? null)})`);
    return sc;
  };

  leg("MCP policyvault_create_org_root_request: a delegate-rule change with a new delegate while the node DAA cannot be read comes back REFUSED with httpStatus 422 and the server's PERIOD_START_REQUIRED refusal verbatim under data; no root request is written [RED on b89f0f7]", async (x) => {
    const before = await x.scope();
    await withMcp(x, ["read:org-roots", "write:org-roots"], async (mcp) => {
      await withAnchor(nodeDown, async () => {
        const sc = refused(await mcp.callTool("r2-06-mcp-1", "policyvault_create_org_root_request", { rootId: T.rootId, action: "authorize", params: { fuel: x.node.seedFuel(KK.p2pkUtxo(w.fee, "r2-06-mcp-1")) }, vaultOperations: [{ vaultId: T.vaultId, action: "ownerSetAgentRoot", params: { agents: [A, B, row(w.n1, "0")] } }], signerAddress: w.o1.address }), "node down");
        assert.equal(sc.status, "REFUSED", `the envelope status (${JSON.stringify(sc.data).slice(0, 300)})`);
        assert.equal(sc.httpStatus, 422);
        assert.equal(sc.data.error.code, "PERIOD_START_REQUIRED");
        assert.equal(typeof sc.data.error.message, "string");
      });
    });
    assert.equal(await x.scope(), before, "nothing is written");
  });

  leg("MCP policyvault_create_org_root_request: the rule's PERIOD_START_STALE refusal comes back REFUSED with httpStatus 409 and the server's code and message verbatim under data [RED on b89f0f7]", async (x) => {
    await withMcp(x, ["read:org-roots", "write:org-roots"], async (mcp) => {
      const err = stale("kas-root-op");
      const sc = refused(await throwing(KK.lazy.wr7, "buildRootActionRequest", () => err, () => mcp.callTool("r2-06-mcp-2", "policyvault_create_org_root_request", { rootId: T.rootId, action: "authorize", params: { fuel: x.node.seedFuel(KK.p2pkUtxo(w.fee, "r2-06-mcp-2")) }, vaultOperations: [{ vaultId: T.vaultId, action: "ownerSetAgentRoot", params: { agents: [A, B, row(w.n1, D)] } }], signerAddress: w.o1.address })), "stale");
      assert.equal(sc.status, "REFUSED");
      assert.equal(sc.httpStatus, 409, `the HTTP status (${JSON.stringify(sc.data).slice(0, 300)})`);
      assert.equal(sc.data.error.code, "PERIOD_START_STALE");
      assert.equal(sc.data.error.message, err.message, "the server's message, verbatim");
    });
  });

  leg("MCP policyvault_create_request: a v4 re-policy of the installed delegate (an ungoverned REDUCTION: a lower per-spend cap, so a changed leaf) while the node DAA cannot be read comes back REFUSED with httpStatus 422 and the server's PERIOD_START_REQUIRED refusal verbatim under data [RED on b89f0f7]", async (x) => {
    await withMcp(x, ["read:vaults", "request:build", "read:requests"], async (mcp) => {
      await withAnchor(nodeDown, async () => {
        const reduced = { ...V4_AGENT(), maxPerSpend: (5n * KAS).toString() };
        const sc = refused(await mcp.callTool("r2-06-mcp-3", "policyvault_create_request", { vaultId: V4.vaultId, action: "rePolicyAgent", signerAddress: w.o1.address, params: { fuel: v4Fuel("mcp-repolicy"), agentPk: reduced.agentPk, agent: reduced } }), "v4 node down");
        assert.equal(sc.status, "REFUSED", `the envelope status (${JSON.stringify(sc.data).slice(0, 300)})`);
        assert.equal(sc.httpStatus, 422, `the HTTP status (${JSON.stringify(sc.data).slice(0, 400)})`);
        assert.equal(sc.data.error.code, "PERIOD_START_REQUIRED");
      });
    });
  });
}
