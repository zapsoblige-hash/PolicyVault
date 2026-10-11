"use strict";
/*
 * RC45 R2-10 — REJECTING A /wallet/v7 REQUEST IS FOR ITS SIGNER OR AN ACTIVE
 * OWNER OF THE VAULT'S ORGANIZATIONAL ROOT; RC45 R2-11 — REJECTING A
 * /wallet/v5 OR /wallet/v6 REQUEST IS FOR ITS SIGNER OR THE CONTROLLER OWNER
 * (sections below); and, on the same template, the scope of RC45 R2-05's
 * stale withdrawal of a slot-signed root request (last section: another
 * profile is never withdrawn as stale). Internal RED-first regression
 * material for the RC45 candidate; not an audit.
 *
 * THE DEFECT (b89f0f7): POST /wallet/v7/requests/:id/reject authorizes with
 * the shared request gate under { mutation: true }, which admits the request's
 * signer OR any principal with build authority on the vault — every owner and
 * every registered delegate. A second delegate of a rooted vault can therefore
 * withdraw another delegate's BUILT (or AWAITING_APPROVALS) request: on a
 * v0.7-kas treasury the request becomes WALLET_REJECTED and the vault-level
 * approvals already collected for it are lost; the same holds for a
 * v0.7-payment request and a v0.7-payment-hd request (one route, one gate). No
 * event or audit row records who withdrew it.
 *
 * REQUIRED BEHAVIOUR (one gate covers the v0.7-kas, v0.7-payment and
 * v0.7-payment-hd branches of the route): after the existing gate (401
 * unauthenticated; 404 REQUEST_NOT_FOUND for a principal that cannot see the
 * request; 403 REQUEST_FORBIDDEN for an approver-only principal), a principal
 * that is neither the request's signer nor an ACTIVE owner slot of the vault's
 * organizational root gets 403 REQUEST_FORBIDDEN — "only the wallet that signs
 * this request or an active owner of the vault's organizational root may
 * reject it" — before any state change: the request record, every other
 * durable record and the audit stay byte-identical, collected approvals
 * included. The signer and an active root owner still withdraw (200). A
 * machine credential acts as the wallet that minted it (an owner-minted one
 * withdraws; a delegate-minted one is refused). The treasury-creation follow-up
 * stays its funder's own. A self-hosted server (tenancy off) is unchanged.
 *
 * RED on b89f0f7 — each named "[RED on b89f0f7]": the lateral rejections by a
 * second delegate (BUILT, AWAITING_APPROVALS with no and with one approval,
 * after a rebuild, through its own machine credential) and the v0.7-payment
 * and v0.7-payment-hd lateral rejections (200 + WALLET_REJECTED today where
 * 403 with nothing written is required).
 * HOLDS on b89f0f7 (and must keep holding): the signer, a root owner and an
 * owner-minted credential withdraw; the approver-only, foreign, successor and
 * unauthenticated refusals; the creation follow-up; the self-hosted control.
 *
 * Hostile principals: a FOREIGN wallet (0x99, no participant of any vault),
 * an UNAUTHENTICATED caller, the pinned successor of the root (no vault
 * participant), an approver-only principal, and a second delegate of the same
 * vault — on every leg family below.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, wallet
 * sessions signed in with TEST keys, machine credentials minted over the real
 * /identities route) over the JSON store and a fresh PostgreSQL database per
 * leg (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a FAIL);
 * the template's root and vaults are built by the real SDK with the real
 * compiler and TEST-key signatures and driven to CHAIN_VERIFIED against an
 * explicit mock chain (sdk/testutil/rc45-r2-az-kit.js). Rejection is a
 * pre-signature, off-chain step: no consensus bytes are produced or changed by
 * any leg here. Realistic delegate period starts (about 5.44e8) and node DAA
 * (5.45e8). Nothing dials a node; TEST keys only; no production data.
 */
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const AZ = require("../testutil/rc45-r2-az-kit");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const { KAS, D, said } = AZ;

const S = AZ.azSuite("r2-az");
let restoreDaa = null;
before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing toolchain is a FAIL, never a SKIP)");
  await S.setup([AZ.seedRootedVaults, AZ.seedTokenControllers]);
  restoreDaa = AZ.useAnchorDaa(D); // a build or check of a new or changed delegate leaf reads the node DAA here
});
after(async () => { if (restoreDaa) restoreDaa(); await S.teardown(); });

const ROOTED_REFUSAL = "only the wallet that signs this request or an active owner of the vault's organizational root may reject it";
const GATE_REFUSAL = "this wallet may review this request; it cannot sign, submit or reject it";

/* the route under test, spelled in full */
const rejectV7 = (x, id, auth) => x.call("POST", ["wallet", "v7", "requests", id, "reject"], {}, auth);
const buildV7 = (x, body, auth) => x.call("POST", ["wallet", "v7", "requests"], body, auth);
const approveV7 = (x, id, body, auth) => x.call("POST", ["wallet", "v7", "requests", id, "approvals"], body, auth);

/* A 403 REQUEST_FORBIDDEN from the rejecter rule with nothing written (record and every durable record unchanged). */
async function refusedLaterally(x, id, auth, label) {
  const before = await x.state(), record = await x.record(id);
  const r = await rejectV7(x, id, auth);
  assert.equal(r.status, 403, `${label}: a non-signer, non-owner participant cannot reject (${said(r)})`);
  assert.equal(r.code, "REQUEST_FORBIDDEN", label);
  assert.equal(r.message, ROOTED_REFUSAL, `${label}: the refusal names who may reject`);
  assert.equal(await x.record(id), record, `${label}: the request record is byte-identical`);
  assert.equal(await x.state(), before, `${label}: no durable record and no audit row was written`);
}
async function withdrawn(x, id, auth, label) {
  const r = await rejectV7(x, id, auth);
  assert.equal(r.status, 200, `${label}: withdrawn (${said(r)})`);
  assert.equal((await x.stored(id)).state, "WALLET_REJECTED", label);
}
async function kasSpend(x, signer, kas, label) {
  const r = await buildV7(x, AZ.kasSpendBody(x.ids, x.w, signer, kas), await x.as(signer));
  assert.equal(r.status, 201, `${label}: delegate spend built (${said(r)})`);
  return r.body.request;
}
async function tokenDeposit(x, vaultId, signer, tag) {
  const r = await buildV7(x, AZ.tokenDepositBody(x.config, vaultId, signer, x.w, tag), await x.as(signer));
  assert.equal(r.status, 201, `${tag}: token deposit built (${said(r)})`);
  return r.body.request.requestId;
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-10 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  /* ---------------- v0.7-kas ---------------- */
  leg("v0.7-kas: a second delegate (B) rejecting the first delegate's (A) BUILT spend is refused 403 REQUEST_FORBIDDEN before any state change — the request record, every durable record and the audit are byte-identical; A then withdraws it itself (200) [RED on b89f0f7]", async (x) => {
    const q = await kasSpend(x, x.w.agentA, 1n, "A's spend");
    assert.equal(q.state, "BUILT");
    await refusedLaterally(x, q.requestId, await x.as(x.w.agentB), "delegate B on A's BUILT spend");
    await withdrawn(x, q.requestId, await x.as(x.w.agentA), "the signer A");
  });

  leg("v0.7-kas: a second delegate (B) rejecting the first delegate's AWAITING_APPROVALS spend is refused 403 with no approval collected and again with one of the two approvals collected — the collected approval is kept and the record stays AWAITING_APPROVALS, byte-identical; A then withdraws it (200) [RED on b89f0f7]", async (x) => {
    const q = await kasSpend(x, x.w.agentA, 3n, "A's above-threshold spend");
    assert.equal(q.state, "AWAITING_APPROVALS");
    assert.equal(q.approvalProgress.required, 2);
    await refusedLaterally(x, q.requestId, await x.as(x.w.agentB), "delegate B, no approval collected");
    const unsigned = (await x.stored(q.requestId)).transaction.unsignedSafeJson;
    const a = await approveV7(x, q.requestId, { approverAddress: x.w.ap1.address, signatureHex: AZ.approvalSignatureHex(x.config, unsigned, x.w.ap1) }, await x.as(x.w.ap1));
    assert.equal(a.status, 200, `approver 1 attaches its approval (${said(a)})`);
    assert.equal(a.body.request.state, "AWAITING_APPROVALS");
    assert.equal(a.body.approvals.collected, 1);
    await refusedLaterally(x, q.requestId, await x.as(x.w.agentB), "delegate B, one approval collected");
    const kept = await x.stored(q.requestId);
    assert.equal(kept.state, "AWAITING_APPROVALS");
    assert.equal(kept.approvalPackage.approvals.filter((s) => typeof s === "string").length, 1, "the collected approval is kept");
    await withdrawn(x, q.requestId, await x.as(x.w.agentA), "the signer A");
  });

  leg("v0.7-kas: repeat after a rebuild — A withdraws its spend and builds it again; B's rejection of the rebuilt request is refused 403 and refused again on a second attempt, nothing written either time [RED on b89f0f7]", async (x) => {
    const first = await kasSpend(x, x.w.agentA, 1n, "A's first spend");
    await withdrawn(x, first.requestId, await x.as(x.w.agentA), "the signer A withdraws the first build");
    const again = await kasSpend(x, x.w.agentA, 1n, "A's rebuilt spend");
    assert.notEqual(again.requestId, first.requestId);
    await refusedLaterally(x, again.requestId, await x.as(x.w.agentB), "delegate B on the rebuilt spend");
    await refusedLaterally(x, again.requestId, await x.as(x.w.agentB), "delegate B again (repeat)");
    assert.equal((await x.stored(again.requestId)).state, "BUILT");
  });

  leg("v0.7-kas: a machine credential minted by delegate B (read:org-roots, write:org-roots) acts as B — its rejection of A's BUILT spend is refused 403 REQUEST_FORBIDDEN, nothing written [RED on b89f0f7]", async (x) => {
    const q = await kasSpend(x, x.w.agentA, 1n, "A's spend");
    const bearerB = await x.credential(x.w.agentB, ["read:org-roots", "write:org-roots"]);
    await refusedLaterally(x, q.requestId, bearerB, "B-minted machine credential");
    assert.equal((await x.stored(q.requestId)).state, "BUILT");
  });

  leg("v0.7-kas (holds): the signer A withdraws its own spend (200); an active root owner withdraws A's spend (200); an owner-minted machine credential withdraws A's spend (200); the approver-only principal is refused at the existing gate (403 REQUEST_FORBIDDEN, unchanged message); a FOREIGN wallet and the pinned successor get the non-oracle 404 REQUEST_NOT_FOUND; an UNAUTHENTICATED caller 401 — no refusal writes anything", async (x) => {
    const q1 = await kasSpend(x, x.w.agentA, 1n, "spend 1");
    for (const wallet of [x.w.ap1, x.w.stranger, x.w.successor]) await x.as(wallet); // sessions first: the snapshot below must see only the refusals
    const before = await x.state();
    const approver = await rejectV7(x, q1.requestId, await x.as(x.w.ap1));
    assert.equal(approver.status, 403, `approver-only (${said(approver)})`);
    assert.equal(approver.code, "REQUEST_FORBIDDEN");
    assert.equal(approver.message, GATE_REFUSAL, "the approver-only refusal is the existing gate's");
    for (const [wallet, label] of [[x.w.stranger, "FOREIGN wallet"], [x.w.successor, "pinned successor (no vault participant)"]]) {
      const r = await rejectV7(x, q1.requestId, await x.as(wallet));
      assert.equal(r.status, 404, `${label} (${said(r)})`);
      assert.equal(r.code, "REQUEST_NOT_FOUND", label);
    }
    const unauth = await rejectV7(x, q1.requestId, null);
    assert.equal(unauth.status, 401, `unauthenticated (${said(unauth)})`);
    assert.equal(await x.state(), before, "no refusal wrote anything");
    await withdrawn(x, q1.requestId, await x.as(x.w.agentA), "the signer A");
    const q2 = await kasSpend(x, x.w.agentA, 1n, "spend 2");
    await withdrawn(x, q2.requestId, await x.as(x.w.o2), "active root owner (slot 2)");
    const q3 = await kasSpend(x, x.w.agentA, 1n, "spend 3");
    await withdrawn(x, q3.requestId, await x.credential(x.w.o1, ["read:org-roots", "write:org-roots"]), "owner-minted machine credential");
  });

  leg("v0.7-kas (holds): the treasury-creation follow-up stays its funder's own — another active root owner and a delegate get the non-oracle 404, the funder (an active root owner) withdraws it (200)", async (x) => {
    const g = await x.call("POST", ["org-roots", x.ids.rootId, "vaults"], {
      profile: "policyvault-0.7-kas", label: "R2 TEST second treasury", agents: [AZ.kasDelegate(x.w.n1, x.w.recipient)], approvers: [], approvalM: 0,
      recoveryAddress: x.w.recovery.address, depositKas: "10", feeReserveKas: "1", signerAddress: x.w.o2.address, funding: [AZ.p2pk(x.w.o2, "second-treasury", 200n)]
    }, await x.as(x.w.o2));
    assert.equal(g.status, 201, `creation built by owner 2 (${said(g)})`);
    assert.equal(g.body.request.kind, "kasGenesis");
    for (const wallet of [x.w.o1, x.w.agentA]) await x.as(wallet); // sessions first: the snapshot below must see only the refusals
    const id = g.body.request.requestId, before = await x.state();
    for (const [wallet, label] of [[x.w.o1, "another active root owner"], [x.w.agentA, "a delegate of the existing treasury"]]) {
      const r = await rejectV7(x, id, await x.as(wallet));
      assert.equal(r.status, 404, `${label} (${said(r)})`);
      assert.equal(r.code, "REQUEST_NOT_FOUND");
    }
    assert.equal(await x.state(), before, "nothing written");
    await withdrawn(x, id, await x.as(x.w.o2), "the funder");
  });

  /* ---------------- v0.7-payment and v0.7-payment-hd (same route, same gate) ---------------- */
  for (const [family, vaultKey] of [["v0.7-payment", "payVaultId"], ["v0.7-payment-hd", "hdVaultId"]]) {
    leg(`${family}: a second delegate (B) rejecting the first delegate's (A) BUILT token deposit is refused 403 REQUEST_FORBIDDEN, the record and every durable record byte-identical; A then withdraws it (200) [RED on b89f0f7]`, async (x) => {
      const id = await tokenDeposit(x, x.ids[vaultKey], x.w.agentA, `${family}-lateral`);
      assert.equal((await x.stored(id)).state, "BUILT");
      await refusedLaterally(x, id, await x.as(x.w.agentB), `${family}: delegate B on A's request`);
      await withdrawn(x, id, await x.as(x.w.agentA), `${family}: the signer A`);
    });
    leg(`${family} (holds): the signer A withdraws its own BUILT token deposit (200) and an active root owner withdraws another of A's (200)`, async (x) => {
      const own = await tokenDeposit(x, x.ids[vaultKey], x.w.agentA, `${family}-own`);
      await withdrawn(x, own, await x.as(x.w.agentA), `${family}: the signer A`);
      const other = await tokenDeposit(x, x.ids[vaultKey], x.w.agentA, `${family}-owner`);
      await withdrawn(x, other, await x.as(x.w.o1), `${family}: active root owner (slot 1)`);
    });
  }
}

/* ---------------- self-hosted (tenancy off; JSON only — PostgreSQL persistence requires hosted authentication) ---------------- */
test("RC45 R2-10 self-hosted (holds): with tenancy off the /wallet/v7 reject route is unchanged — a v0.7-kas delegate spend built for A is withdrawn by an unauthenticated call (200, WALLET_REJECTED)", async () => {
  const x = await S.fresh("self-hosted");
  try {
    const q = await kasSpend(x, x.w.agentA, 1n, "self-hosted spend");
    await withdrawn(x, q.requestId, null, "self-hosted caller");
  } finally { await S.release(x); }
});

/*
 * RC45 R2-11 — /wallet/v5 AND /wallet/v6 (token controllers; testnet-only
 * generations).
 *
 * THE DEFECT (b89f0f7): POST /wallet/v{5,6}/requests/:id/reject authorizes
 * with the token surface's request gate under { mutation: true }, which admits
 * the request's signer OR any wallet with build authority — the controller
 * owner and every registered agent. A registered agent can therefore withdraw
 * the owner's BUILT ownerPause, ownerRecover or ownerSetAgentRoot (v0.6 also
 * ownerSetSwapRoot), and another agent's BUILT spend.
 *
 * REQUIRED BEHAVIOUR: after the existing gate (401 unauthenticated; 404
 * REQUEST_NOT_FOUND for a principal that cannot see the request), a principal
 * that is neither the request's signer nor the controller owner
 * (template.owner) gets 403 REQUEST_FORBIDDEN — "only the wallet that signs
 * this request or the vault owner may reject it" — before any state change,
 * every durable record and the audit byte-identical. The owner withdraws its
 * own requests and an agent's; an agent withdraws its own. A self-hosted
 * server is unchanged.
 *
 * RED on b89f0f7: an agent on each of the owner's BUILT owner operations, and
 * the second agent on the first agent's BUILT token spend (200 +
 * WALLET_REJECTED today). HOLDS: the owner and signer withdrawals, the FOREIGN
 * wallet's non-oracle 404, the UNAUTHENTICATED 401, the self-hosted control.
 * Same layers as above (real v0.5 / v0.6 controller builders and compiler,
 * TEST keys, JSON and PostgreSQL, nothing dials a node).
 */
const TOKEN_REFUSAL = "only the wallet that signs this request or the vault owner may reject it";
/* the routes under test, spelled in full */
const rejectV5 = (x, id, auth) => x.call("POST", ["wallet", "v5", "requests", id, "reject"], {}, auth);
const rejectV6 = (x, id, auth) => x.call("POST", ["wallet", "v6", "requests", id, "reject"], {}, auth);
const buildV5 = (x, body, auth) => x.call("POST", ["wallet", "v5", "requests"], body, auth);
const buildV6 = (x, body, auth) => x.call("POST", ["wallet", "v6", "requests"], body, auth);
const TOKEN = {
  v5: { reject: rejectV5, build: buildV5, vaultKey: "v5VaultId", covKey: "v5CovenantId", ownerOps: ["ownerPause", "ownerRecover", "ownerSetAgentRoot"] },
  v6: { reject: rejectV6, build: buildV6, vaultKey: "v6VaultId", covKey: "v6CovenantId", ownerOps: ["ownerPause", "ownerRecover", "ownerSetAgentRoot", "ownerSetSwapRoot"] }
};
function ownerOpExtra(x, gen, action) {
  if (action === "ownerSetAgentRoot") {
    const policy = gen === "v6" ? AZ.tokenPolicyV6 : AZ.tokenPolicy;
    return { newAgents: [AZ.policyOnly(policy(x.w.agentA, x.w.recipient))] }; // agent B removed
  }
  if (action === "ownerSetSwapRoot") return { newSwapRoot: AZ.H(0x77) };
  return {};
}
async function tokenOwnerOp(x, gen, action) {
  const t = TOKEN[gen];
  const r = await t.build(x, AZ.ownerOpBody(x.ids[t.vaultKey], x.w, action, ownerOpExtra(x, gen, action), `${gen}-${action}`), await x.as(x.w.o1));
  assert.equal(r.status, 201, `${gen} ${action} built by the owner (${said(r)})`);
  assert.equal(r.body.request.state, "BUILT");
  return r.body.request.requestId;
}
async function tokenSpend(x, gen, signer) {
  const t = TOKEN[gen];
  const r = await t.build(x, AZ.tokenSpendBody(x.config, gen, x.ids[t.vaultKey], x.ids[t.covKey], signer, x.w), await x.as(signer));
  assert.equal(r.status, 201, `${gen} token spend built for ${signer.xonly.slice(0, 8)} (${said(r)})`);
  assert.equal(r.body.request.state, "BUILT");
  return r.body.request.requestId;
}
async function tokenRefused(x, gen, id, auth, label) {
  const before = await x.state(), record = await x.record(id);
  const r = await TOKEN[gen].reject(x, id, auth);
  assert.equal(r.status, 403, `${label}: neither the signer nor the controller owner may reject (${said(r)})`);
  assert.equal(r.code, "REQUEST_FORBIDDEN", label);
  assert.equal(r.message, TOKEN_REFUSAL, `${label}: the refusal names who may reject`);
  assert.equal(await x.record(id), record, `${label}: the request record is byte-identical`);
  assert.equal(await x.state(), before, `${label}: no durable record and no audit row was written`);
}
async function tokenWithdrawn(x, gen, id, auth, label) {
  const r = await TOKEN[gen].reject(x, id, auth);
  assert.equal(r.status, 200, `${label}: withdrawn (${said(r)})`);
  assert.equal((await x.stored(id)).state, "WALLET_REJECTED", label);
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-11 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });
  for (const gen of ["v5", "v6"]) {
    for (const action of TOKEN[gen].ownerOps) {
      leg(`/wallet/${gen}: a registered agent (A) rejecting the controller owner's BUILT ${action} is refused 403 REQUEST_FORBIDDEN before any state change, every durable record byte-identical; the owner then withdraws it (200) [RED on b89f0f7]`, async (x) => {
        const id = await tokenOwnerOp(x, gen, action);
        await tokenRefused(x, gen, id, await x.as(x.w.agentA), `${gen} agent A on the owner's ${action}`);
        await tokenWithdrawn(x, gen, id, await x.as(x.w.o1), `${gen} owner withdraws its ${action}`);
      });
    }
    leg(`/wallet/${gen}: a second registered agent (B) rejecting agent A's BUILT token spend is refused 403 REQUEST_FORBIDDEN, every durable record byte-identical; A then withdraws it (200) [RED on b89f0f7]`, async (x) => {
      const id = await tokenSpend(x, gen, x.w.agentA);
      await tokenRefused(x, gen, id, await x.as(x.w.agentB), `${gen} agent B on A's spend`);
      await tokenWithdrawn(x, gen, id, await x.as(x.w.agentA), `${gen} the signer A`);
    });
    leg(`/wallet/${gen} (holds): the owner withdraws its own BUILT ownerPause (200) and agent A's BUILT token spend (200); agent A withdraws its own spend (200); a FOREIGN wallet gets the non-oracle 404 REQUEST_NOT_FOUND and an UNAUTHENTICATED caller 401, writing nothing`, async (x) => {
      const pause = await tokenOwnerOp(x, gen, "ownerPause");
      const spend1 = await tokenSpend(x, gen, x.w.agentA);
      const stranger = await x.as(x.w.stranger), before = await x.state();
      for (const id of [pause, spend1]) {
        const foreign = await TOKEN[gen].reject(x, id, stranger);
        assert.equal(foreign.status, 404, `FOREIGN wallet (${said(foreign)})`);
        assert.equal(foreign.code, "REQUEST_NOT_FOUND");
        const unauth = await TOKEN[gen].reject(x, id, null);
        assert.equal(unauth.status, 401, `unauthenticated (${said(unauth)})`);
      }
      assert.equal(await x.state(), before, "no refusal wrote anything");
      await tokenWithdrawn(x, gen, pause, await x.as(x.w.o1), `${gen} owner, own ownerPause`);
      await tokenWithdrawn(x, gen, spend1, await x.as(x.w.o1), `${gen} owner, agent A's spend`);
      const spend2 = await tokenSpend(x, gen, x.w.agentA);
      await tokenWithdrawn(x, gen, spend2, await x.as(x.w.agentA), `${gen} agent A, own spend`);
    });
  }
}

test("RC45 R2-11 self-hosted (holds): with tenancy off the /wallet/v5 and /wallet/v6 reject routes are unchanged — the owner's BUILT ownerPause on each controller is withdrawn by an unauthenticated call (200, WALLET_REJECTED)", async () => {
  const x = await S.fresh("self-hosted");
  try {
    for (const gen of ["v5", "v6"]) {
      const id = await tokenOwnerOp(x, gen, "ownerPause");
      await tokenWithdrawn(x, gen, id, null, `${gen} self-hosted caller`);
    }
  } finally { await S.release(x); }
});

/* ======================= RC45 R2-05 — the stale-withdrawal scope: another profile =======================
 * A delegate-rule change that carries owner slot signatures can be withdrawn because its delegate period start aged
 * out ONLY when it is a v0.7-kas ownerSetAgentRoot. A never-attempted, slot-signed delegate-rule change on the rooted
 * v0.7-payment vault of the same root, whose delegate starts lie far behind the node, keeps 409 CANNOT_REJECT.
 * HOLDS on b89f0f7 (and must keep holding). The withdrawal is judged with the node DAA seam far past every start. */
const R2_05_FAR = D + 100n * 864000n;
async function rootSlotSign(x, rootId, id, slot, wallet) {
  const cookie = await x.as(wallet);
  const env = await x.call("GET", ["org-roots", rootId, "requests", id, "slot-request", String(slot)], null, cookie);
  assert.equal(env.status, 200, `slot ${slot} signing request (${said(env)})`);
  const e = env.body.slotRequest, q = await require("../src/wallet-requests-v7").loadOrgRootRequest(x.config, id);
  const response = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: e.requestVersion, requestId: e.requestId, network: e.network, manifestHash: e.manifestHash, txId: e.txId, root: e.root, slot: e.slot, signerAddress: wallet.address, signatureHex: AZ.KK.slotSignatureHex(x.config, q.transaction.unsignedSafeJson, q.rootInputIndex, wallet), sighashType: 1, signedAtMs: Date.now() };
  const r = await x.call("POST", ["org-roots", rootId, "requests", id, "slot-signatures"], { slot, response }, cookie);
  assert.equal(r.status, 200, `slot ${slot} signature attached (${said(r)})`);
}
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  test(`RC45 R2-05 ${backend} (holds): stale-withdrawal scope — a never-attempted delegate-rule change on the rooted v0.7-payment vault (another profile) carrying two owner slot signatures, whose delegate starts lie far behind the node, is NOT withdrawn: 409 CANNOT_REJECT, every request, root, vault, claim and receipt record byte-identical, the root still reserves it`, { skip }, async () => {
    const x = await S.fresh(backend);
    try {
      const { w, ids } = x;
      const wr7 = require("../src/wallet-requests-v7");
      const agents = [AZ.tokenPolicy(w.agentA, w.recipient), { ...AZ.tokenPolicy(w.agentB, w.recipient), tokenMaxPerSpend: "400" }];
      const built = await require("../testutil/guard-node").withFixtureNode(x.config, async () => x.call("POST", ["org-roots", ids.rootId, "requests"], { action: "authorize", params: { fuel: require("../testutil/guard-node").seedFixtureFuel(x.config, AZ.p2pk(w.fuel, "r2-05-scope-payment")) } /* R3N-B1a inventory: the supplied fee UTXO is on the fixture node before the build reads it */, vaultOperations: [{ vaultId: ids.payVaultId, action: "ownerSetAgentRoot", params: { agents } }], signerAddress: w.o1.address }, await x.as(w.o1)));  // RC45 L2-01 guard inventory: the build reads the template chain
      assert.equal(built.status, 201, `the payment-vault delegate-rule change is built (${said(built)})`);
      const id = built.body.request.id;
      await rootSlotSign(x, ids.rootId, id, 1, w.o1);
      await rootSlotSign(x, ids.rootId, id, 2, w.o2);
      const q = await wr7.loadOrgRootRequest(x.config, id);
      assert.equal(q.state, "AUTHORIZED");
      assert.equal(q.slots.filter((s) => s.status === "SIGNED").length, 2, "two owner slot signatures are attached");
      assert.equal(q.vaultOperations[0].action, "ownerSetAgentRoot");
      assert.equal(q.vaultOperations[0].profile, "policyvault-0.7-payment", "another profile");
      assert.ok(Array.isArray(q.newRegistry) && q.newRegistry.every((e) => BigInt(R2_05_FAR) - BigInt(e.periodStartDaa) > BigInt(e.periodLengthDaa)), "every stored delegate start lies far more than a period behind the judging position");
      const before = await AZ.KK.scope(x.config);
      const restore = AZ.useAnchorDaa(R2_05_FAR);
      let r;
      try { r = await x.call("POST", ["org-roots", ids.rootId, "requests", id, "reject"], { reason: "RC45 R2 TEST withdrawal" }, await x.as(w.o1)); } finally { restore(); }
      assert.equal(r.status, 409, `another profile's slot-signed request is never withdrawn as stale (${said(r)})`);
      assert.equal(r.code, "CANNOT_REJECT");
      assert.equal(await AZ.KK.scope(x.config), before, "nothing is written (every request, root, vault, claim and receipt record is byte-identical)");
      assert.equal((await wr7.loadOrgRoot(x.config, ids.rootId)).pendingRequestId, id, "the root still reserves it");
    } finally { await S.release(x); }
  });
}
