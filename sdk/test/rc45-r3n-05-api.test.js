"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — the SERVED surfaces: the reconcile route's attributed answer (owner session and an
 * owner-minted machine credential), the attribution marker on the served request, the UNRESOLVED treasury in both vault
 * summaries, the HTTP status of the two new refusal codes, and the pinned attestation behaviour for v0.7-kas root
 * requests. Internal RED-first regression material for the RC45 candidate; not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR (contract revision 2 §1 D5, D7, D8 and addendum a item 4):
 *   - POST /org-roots/:id/reconcile serves the ADVANCED attribution answer (via, mode, depth, treasury, settled,
 *     unsettled, holds, buildable) to the owner session and to an owner-minted write:org-roots credential;
 *   - GET /org-roots/:id/requests/:id serves A's outOfBandAttribution marker (presentOrgRootRequest passes it through);
 *   - GET /org-roots/:id/vaults and GET /wallet/v7/vaults carry stateUnresolved { requestId, txId } for the UNRESOLVED
 *     treasury and null for the others, one listing per root;
 *   - STATUS_BY_CODE: RECORDED_OUTPUT_SPENT and TREASURY_STATE_UNRESOLVED are 409;
 *   - ATT-01 (re-scoped by addendum a): the existing behaviour is pinned, not changed — an attestation of a v0.7-kas
 *     root request is refused 500 ATTESTATION_MANIFEST_VERSION_UNKNOWN (server/src/attestations-v7.js, the manifest
 *     version check), before and after an attribution (finding FU-ATT-01 is classified separately).
 *
 * Layers and labels as in sdk/test/rc45-r3n-01-attribution.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const SC = require("../testutil/rc45-r3n-scenario");
const { said } = KK;
const { lower, OOB_SCHEMA } = SC;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const X_ = SC.scenario("r3n05");
const { ctx } = X_;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await X_.setup();
});
after(async () => { await X_.teardown(); });

const attestation = (x, request) => require("../../server/src/attestations").buildAttestationForRequest(x.config, request);
async function attestationRefused(x, requestId, label) {
  const q = await x.rootReq(requestId);
  await assert.rejects(attestation(x, q), (e) => {
    assert.equal(e.status, 500, `${label}: 500 (${e.code} ${e.message})`);
    assert.equal(e.code, "ATTESTATION_MANIFEST_VERSION_UNKNOWN", `${label}: ATTESTATION_MANIFEST_VERSION_UNKNOWN`);
    return true;
  });
}

test("RC45 L2-01: WEB-02 (API) STATUS_BY_CODE answers 409 for RECORDED_OUTPUT_SPENT and TREASURY_STATE_UNRESOLVED (a refusal of a conflict with recorded chain state, never a 422 validation answer) [RED on 8877dee]", () => {
  const { mapError } = require("../../server/src/org-roots");
  for (const code of ["RECORDED_OUTPUT_SPENT", "TREASURY_STATE_UNRESOLVED"]) {
    const e = mapError(Object.assign(new Error(`TEST ${code}`), { code }));
    assert.equal(e.status, 409, `${code} is 409`);
    assert.equal(e.code, code);
  }
});

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", X_.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 L2-01 ${backend}: ${name}`, { skip }, async () => { const x = await X_.fresh(backend); try { await fn(x); } finally { await X_.release(x); } });

  leg("ATR (route) POST /org-roots/:id/reconcile serves the ADVANCED attribution answer to the owner session; an owner-minted write:org-roots machine credential then reads CONSISTENT; GET /org-roots/:id/requests/:A serves A's attribution marker [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "api-route");
    const r = await X_.verifyRoute(x);
    assert.equal(r.status, 200, `the reconcile route (${said(r)})`);
    X_.assertAttributedAdvanced(r.body.reconcile, f, { label: "the reconcile route" });
    assert.ok(Array.isArray(r.body.reconcile.root.holds) && r.body.reconcile.root.buildable && typeof r.body.reconcile.root.buildable.root === "boolean", "holds and buildable are served");
    const token = await x.credential(["read:org-roots", "write:org-roots"]);
    const r2 = await X_.verifyRoute(x, { auth: { authorization: `Bearer ${token}` } });
    assert.equal(r2.status, 200, `the machine credential's reconcile (${said(r2)})`);
    assert.equal(r2.body.reconcile.root.status, "CONSISTENT");
    const got = await x.call("GET", ["org-roots", ctx.rootId, "requests", f.A], null, x.cookie.o1);
    assert.equal(got.status, 200, said(got));
    const m = got.body.request.outOfBandAttribution;
    assert.ok(m, "the served request carries the attribution marker");
    assert.equal(m.schema, OOB_SCHEMA);
    assert.equal(m.via, "attribution");
    assert.equal(lower(m.txId), f.X);
    assert.equal(m.mode, "FULL");
    assert.equal(got.body.request.state, "CHAIN_VERIFIED");
  });

  leg("UNR-04 PARTIAL: GET /org-roots/:id/vaults and GET /wallet/v7/vaults present T1 with stateUnresolved { requestId: A, txId } and T2 with stateUnresolved null, each treasury listed once [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "unr04", { mode: "PARTIAL" });
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL" });
    for (const [label, segments] of [["GET /org-roots/:id/vaults", ["org-roots", ctx.rootId, "vaults"]], ["GET /wallet/v7/vaults", ["wallet", "v7", "vaults"]]]) {
      const res = await x.call("GET", segments, null, x.cookie.o1);
      assert.equal(res.status, 200, `${label} (${said(res)})`);
      const t1s = res.body.vaults.filter((v) => v.vaultId === ctx.T1), t2s = res.body.vaults.filter((v) => v.vaultId === ctx.T2);
      assert.equal(t1s.length, 1, `${label}: T1 listed once`);
      assert.equal(t2s.length, 1, `${label}: T2 listed once`);
      assert.deepEqual(t1s[0].stateUnresolved, { requestId: f.A, txId: f.X }, `${label}: T1 carries its UNRESOLVED state`);
      assert.equal(t2s[0].stateUnresolved, null, `${label}: T2 carries stateUnresolved null`);
    }
  });

  leg("WEB-02 (route) the two codes reach a client as 409: a root build after A's confirmation below the depth answers 409 RECORDED_OUTPUT_SPENT; after a PARTIAL attribution a T1 delegate build answers 409 TREASURY_STATE_UNRESOLVED [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "web02r", { mode: "PARTIAL", depth: 10n });
    const b = await X_.rootOnly(x, "freeze", "web02r-fz");
    assert.equal(b.status, 409, said(b));
    assert.equal(b.code, "RECORDED_OUTPUT_SPENT");
    x.node.state.daa += 1000n;
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL", depth: "1010" });
    const d = await X_.delegateBuild(x, ctx.T1);
    assert.equal(d.status, 409, said(d));
    assert.equal(d.code, "TREASURY_STATE_UNRESOLVED");
  });

  leg("ATT-01 (re-scoped: pins the existing behaviour) the attestation of an ordinary hosted v0.7-kas root request that reached CHAIN_VERIFIED is refused 500 ATTESTATION_MANIFEST_VERSION_UNKNOWN, and so is the attestation of the v0.7-kas root request A before and after the Verify at depth [PIN: holds on 8877dee]", async (x) => {
    const ok = await X_.ops.pause(x, ctx.T2, "att01-pz2");
    await attestationRefused(x, ok.id, "an ordinary CHAIN_VERIFIED v0.7-kas root request");
    const f = await X_.caseFive(x, "att01");
    await attestationRefused(x, f.A, "A before the Verify");
    await X_.verify(x);
    await attestationRefused(x, f.A, "A after the Verify");
  });
}
