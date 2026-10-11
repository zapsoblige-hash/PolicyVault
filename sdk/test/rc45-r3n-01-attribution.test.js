"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — ATTRIBUTION of a case-5 root move confirmed outside PolicyVault, its completion
 * (FULL and PARTIAL), the UNRESOLVED treasury, contradictions, boundaries and crash replay. Internal RED-first
 * regression material for the RC45 candidate; not an external engagement of any kind.
 *
 * THE DEFECT (8877dee, introduced by R2: finalize refuses a stale delegate-rule change): a delegate-rule change A on
 * treasury T1, signed by the owners and refused at finalize PERIOD_START_STALE (withdrawn or not), can still be
 * assembled from the owners' approvals and the fee key and confirmed OUTSIDE PolicyVault. The root's recorded outpoint
 * P is then gone with no claim, Verify answers UNKNOWN forever, and every hosted action on the root and on every
 * treasury it carries — FREEZE included — is lost (root-wide).
 *
 * REQUIRED BEHAVIOUR (contract revision 2 + addendum a, the RED list legs named in each title):
 *   - D1/D2 attribution: in the live-outpoint-gone branch, after the claim path fails, records first (candidates on P
 *     with a txid and a build; none -> the unchanged UNKNOWN with no further node read), then fresh exact observation of
 *     the candidate root successors, the binding of A's frozen bytes / manifest transaction / root input to P, the
 *     consistency of A's inputs, T1's successor read (FULL: exact; PARTIAL: nothing under A's txid), the bracket
 *     re-read, and the depth rule (>= 1,000 DAA); anything else answers UNKNOWN with
 *     attribution { outcome, requestId?, txId?, depthDaa?, requiredDepthDaa: "1000" } and writes nothing;
 *   - D3 completion: ADVANCED { via: "attribution", mode, depthDaa, requiredDepthDaa, treasury, settled, unsettled,
 *     holds, buildable }; FULL advances T1 to A's successor with A's registry; PARTIAL never writes T1 and records it
 *     UNRESOLVED; the marker outOfBandAttribution (schema policyvault-oob-attribution/1) is the first durable write and
 *     every crash after it is replayed exactly once by the next Verify or Submit;
 *   - D7: an UNRESOLVED treasury refuses every hosted action 409 TREASURY_STATE_UNRESOLVED naming A and its txid,
 *     ahead of VAULT_PAUSED / VAULT_PENDING_REQUEST (the root-wide ROOT_PENDING_REQUEST still first);
 *   - addendum a: a FULL replay whose T1 is no longer at its predecessor completes FULL without reading T1; a FULL
 *     replay whose T1 output was spent downgrades to PARTIAL in one save (treasury.state UNRESOLVED); a PARTIAL replay
 *     never reads T1; a discovery replay of a bound marker answers with the attribution fields;
 *   - writer decision 'PARTIAL upgrade' (C4-03a; supersedes "PARTIAL never upgrades" for a LATER Verify): a later Verify
 *     that freshly observes A's T1 successor exact and unspent at depth >= 1,000 advances T1 to A's successor with A's
 *     registry and records mode FULL with the upgrade; while that output is absent or contradictory nothing is written.
 *     C4-03c (the C4-03b item check): a crash inside the upgrade never leaves Verify throwing, the root held or the
 *     marker FULL over a spent T1 record, also once the root moved on and the restored output is spent again; each
 *     upgrade rule is pinned on its own; the replay answer never claims that a root which moved on follows A's
 *     successor; the upgrade appends one event line.
 *     C4-04a (the C4-03d and C4-03b item checks, contract D2.2): a crash inside the Verify that downgrades the marker
 *     never leaves the root held; the upgrade's event line follows T1's write and a failed line is never reported as an
 *     upgrade; the replay wording names the root record's actual position; the replay exemption covers only a treasury
 *     record at its predecessor; the upgrade needs A's durable completion verified; more than 64 distinct candidate
 *     root successor addresses answer CANDIDATE_CAP before any of them is read.
 *     C4-08a (the C4 sabotage gate's findings SAB04-F02 and SAB04-F01): exactly one failed T1 write inside the upgrade,
 *     every other write succeeding, is never reported as an upgrade and leaves T1's record unwritten until the next
 *     Verify completes the upgrade once; A's records claiming another transaction id with A's frozen bytes intact (the
 *     manifest hash recomputed, the node reporting A's outputs under that id) answer RECORD_DAMAGED and write nothing.
 *
 * Layers: SDK (reconcileOrgRootV7 over an explicit node) plus API (the real server/src/api.js handle in hosted mode,
 * owner and delegate wallet sessions signed in with TEST keys), over the JSON store and a fresh PostgreSQL database per
 * leg. Real v0.7 root / v0.7-kas compiler and encoder; every hosted finalize runs the pinned VM preflight over the
 * assembled transaction; the owners' own exit (BND-01) is built with existing SDK functions and checked on the real
 * VM. Every node observation comes from the explicit mock chain (accepting-DAA stamps on). Labels: [RED on 8877dee]
 * fails on C3 for the stated reason; [PIN: holds on 8877dee] passes on C3 and must keep passing (a C4-only detail is
 * checked only when the answer carries it).
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { test, before, after } = require("node:test");
const SC = require("../testutil/rc45-r3n-scenario");
const { K, KAS, D, said, withAnchor } = KK;
const { DEPTH, STALE, lower, sameOp } = SC;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const X_ = SC.scenario("r3n01");
const { ctx } = X_;
const C = () => KK.lazy.store.Categories;
const wr7 = () => KK.lazy.wr7;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await X_.setup();
});
after(async () => { await X_.teardown(); });

/* every record family byte-identical across `fn`, and no event line added */
async function writesNothing(x, label, fn) {
  const scope0 = await x.scope(), ev0 = await X_.eventCount(x);
  const out = await fn();
  assert.equal(await x.scope(), scope0, `${label}: nothing is written (every request, root, vault, claim and receipt record is byte-identical)`);
  assert.equal(await X_.eventCount(x), ev0, `${label}: no event line is added`);
  return out;
}
async function refused(x, label, call, status, code) {
  return writesNothing(x, label, async () => {
    const r = await call();
    assert.equal(r.status, status, `${label} (${said(r)})`);
    assert.equal(r.code, code, `${label}: ${code} (${said(r)})`);
    return r;
  });
}
const t1Registry = (x) => x.installed(ctx.T1);
/* The C4-only attribution detail of an UNKNOWN answer (contract D2.10: attribution { outcome, requestId?, txId?,
 * depthDaa?, requiredDepthDaa: "1000" }). A [PIN] leg checks it only when the answer carries it (C3 carries none); its
 * paired "(detail)" [RED] leg runs the same body and REQUIRES it, so a C4 that leaves the detail out fails there. */
const DETAIL = {
  PIN: (r, outcome, label) => X_.ifAttribution(r, outcome, label),
  RED: (r, outcome, label) => X_.assertAttributionOutcome(r, outcome, { label })
};

/* ---- bodies shared by a [PIN] leg and its "(detail)" [RED] leg; `detail` is DETAIL.PIN or DETAIL.RED ---- */
async function ctr01(x, detail) {
  const f = await X_.caseFive(x, "ctr01");
  const succ = X_.rootSuccessorAddress(x, f.recA), live = (await X_.rootRec(x)).live.address;
  x.node.afterRead((c) => c.method === "getUtxosByAddresses" && c.addresses.includes(succ), succ === live ? 2 : 1, () => x.node.spendOutpoint(f.rootOut));
  const r = await writesNothing(x, "root successor spent mid-Verify", () => X_.verify(x));
  X_.assertUnknown(r, "CTR-01");
  detail(r, "UNSTABLE", "CTR-01");
}
async function ctr02(x, detail) {
  const f = await X_.caseFive(x, "ctr02");
  const t1succ = X_.vaultSuccessorAddress(x, f.recA);
  x.node.afterRead((c) => c.method === "getUtxosByAddresses" && c.addresses.includes(t1succ), 1, () => x.node.spendOutpoint(f.vaultOut));
  const r = await writesNothing(x, "T1 successor spent mid-Verify", () => X_.verify(x));
  X_.assertUnknown(r, "CTR-02");
  detail(r, "UNSTABLE", "CTR-02");
}
async function ctr04(x, detail) {
  const f = await X_.caseFive(x, "ctr04");
  const otherScript = `20${"11".repeat(32)}ac`;
  const patches = (e) => [
    ["value", { amount: e.amount + 1n }],
    ["covenant id", { covenantId: K.hex("rc45-l201-ctr04-other-covenant") }],
    ["script", { scriptPublicKey: { version: 0, script: otherScript } }],
    ["null script", { scriptPublicKey: { version: 0, script: null } }]
  ];
  for (const [side, outpoint] of [["root successor", f.rootOut], ["T1 successor", f.vaultOut]]) {
    const e = x.node.entryAt(outpoint).entry;
    for (const [what, patch] of patches(e)) {
      const label = `${side}: ${what}`;
      const restore = x.node.mutateEntry(outpoint, patch);
      const r = await writesNothing(x, label, () => X_.verify(x));
      X_.assertUnknown(r, label);
      detail(r, "CONTRADICTION", label);
      restore();
    }
  }
}
async function ctr05(x, detail) {
  const f = await X_.caseFive(x, "ctr05");
  KK.seedFee(x, f.recA);
  const r = await writesNothing(x, "an input of A present", () => X_.verify(x));
  X_.assertUnknown(r, "CTR-05");
  detail(r, "CONTRADICTION", "CTR-05");
}
async function ctr06(x, detail) {
  const f = await X_.caseFive(x, "ctr06");
  for (const raw of ["0x2f", "-5", "12.5", null]) {
    const label = `blockDaaScore ${JSON.stringify(raw)}`;
    const restore = x.node.mutateEntry(f.rootOut, { daaStamp: raw });
    const r = await writesNothing(x, label, () => X_.verify(x));
    X_.assertUnknown(r, label);
    detail(r, "OBSERVATION_ERROR", label);
    restore();
  }
}
async function ctr07(x, detail) {
  const f = await X_.caseFive(x, "ctr07");
  const stamp = x.node.entryAt(f.vaultOut).entry.daaStamp;
  x.node.mutateEntry(f.vaultOut, { daaStamp: (BigInt(stamp) + 1n).toString() });
  const r = await writesNothing(x, "T1 and root DAA differ", () => X_.verify(x));
  X_.assertUnknown(r, "CTR-07");
  detail(r, "CONTRADICTION", "CTR-07");
}
async function dup01(x, detail) {
  const f = await X_.caseFive(x, "dup01");
  const clone = structuredClone(await x.store.read(C().ORG_ROOT_REQUEST, f.A));
  clone.id = crypto.randomUUID();
  await x.store.write(C().ORG_ROOT_REQUEST, clone.id, clone);
  const r = await writesNothing(x, "duplicate records", () => X_.verify(x));
  X_.assertUnknown(r, "DUP-01");
  detail(r, "AMBIGUOUS", "DUP-01");
}
async function bnd01(x, detail) {
  const f = await X_.caseFive(x, "bnd01");
  const succ = await KK.successorsOf(x, f.recA, { rootId: ctx.rootId, vaultId: ctx.T1 });
  const ep = KK.offlineOwnerOp(x, { vault: succ.vault, root: succ.root, rootId: ctx.rootId, action: "ownerEmergencyPause", signers: [1], tag: "r3n01-bnd01" });
  assert.equal(ep.vm, "PASS", "the owners' exit passes the real VM");
  x.node.expectFrozen(ep.build.frozen, ep.txId);
  x.node.state.effects.get(ep.txId)();
  x.node.state.daa += 2000n;
  const r = await writesNothing(x, "Verify after the owners' exit", () => X_.verify(x));
  X_.assertUnknown(r, "BND-01");
  detail(r, "NO_CANDIDATE", "BND-01");
  assert.equal((await x.rootReq(f.A)).state, "REFUSED");
  assert.equal(await X_.receiptOf(x, f.X), null, "no receipt for A's txid");
}
async function bnd03(x, detail) {
  const recA = await X_.caseFiveA(x, "bnd03");
  const P = X_.predecessorOf(recA);
  x.node.spendOutpoint(P);
  x.node.putEntry(ctx.w.stranger.address, { outpoint: { transactionId: K.hex("rc45-l201-bnd03-foreign-tx"), index: 0 }, amount: 2n * KAS, covenantId: null, scriptPublicKey: { version: 0, script: `20${ctx.w.stranger.xonly}ac` } });
  x.node.state.daa += 2n * DEPTH;
  const r = await writesNothing(x, "Verify after a foreign spend", () => X_.verify(x));
  X_.assertUnknown(r, "BND-03");
  detail(r, "NO_CANDIDATE", "BND-03");
}
async function bnd05(x, detail) {
  const f = await X_.caseFive(x, "bnd05");
  const succ = X_.rootSuccessorAddress(x, f.recA), live = (await X_.rootRec(x)).live.address, t1succ = X_.vaultSuccessorAddress(x, f.recA);
  const variants = [
    ["the DAA read", X_.faultyRpc(x.node.rpc, { method: "getBlockDagInfo", always: true })],
    ["the read of A's root successor address", X_.faultyRpc(x.node.rpc, { method: "getUtxosByAddresses", pred: ({ addresses }) => addresses.map(String).includes(succ), nth: succ === live ? 2 : 1 })],
    ["the read of T1's successor address", X_.faultyRpc(x.node.rpc, { method: "getUtxosByAddresses", pred: ({ addresses }) => addresses.map(String).includes(t1succ), nth: 1 })]
  ];
  for (const [label, rpc] of variants) {
    const r = await writesNothing(x, label, () => X_.verify(x, { rpc }));
    X_.assertUnknown(r, label);
    detail(r, "OBSERVATION_ERROR", label);
  }
}

/* ---- RC45 C4-03a (tests only): legs for the C4-03 item-check findings F-01 (the completion's own fresh T1
 * re-observation), F-02 (completion-stage refusal and node read error), F-03 (the D1 gate) and for the WRITER DECISION
 * 'PARTIAL upgrade'. Their labels name the C4-03 head: [RED on d79f710] fails there for the stated reason; [PIN: holds
 * on d79f710] passes there and must keep passing. ---- */
const isReadOf = (address) => (c) => c.method === "getUtxosByAddresses" && c.addresses.includes(address);
const readsSince = (x, address, from) => x.node.reads().slice(from).filter(isReadOf(address)).length;
/* the address of A's input carrying T1's covenant (T1's recorded predecessor) */
function t1InputAddress(x, rec) {
  const input = rec.build.frozen.inputs.find((i) => lower(i.utxo.covenantId ?? "") === lower(rec.build.covenantId));
  assert.ok(input, "A spends T1's predecessor");
  return SC.spkAddress(x.config, input.utxo.scriptPublicKey);
}
/* an rpc whose UTXO answers omit `outpoint` (a node transiently not reporting an output that is on chain throughout) */
function omittingRpc(base, outpoint) {
  return { ...base, async getUtxosByAddresses(args) { const r = await base.getUtxosByAddresses(args); return { ...r, entries: r.entries.filter((e) => !sameOp(e.outpoint, outpoint)) }; } };
}
/* PARTIAL with a reversible payment: A confirmed outside PolicyVault (FULL so far), the node's entries for T1's
 * predecessor and for A's T1 successor kept exactly as reported (address, value, covenant id, script, accepting-DAA
 * stamp), then a delegate of A pays from T1's new output outside PolicyVault (spending only that output). */
async function partialCase(x, tag) {
  const t1Pred = x.node.entryAt((await x.vault(ctx.T1)).live.outpoint);
  assert.ok(t1Pred, `${tag}: T1's recorded output is on the mock chain`);
  const f = await X_.caseFive(x, tag);
  const t1Entry = x.node.entryAt(f.vaultOut);
  assert.ok(t1Entry, `${tag}: A's T1 successor is on the mock chain`);
  const spend = await X_.spendT1Successor(x, f.recA);
  assert.deepEqual(spend.build.frozen.inputs.map((i) => `${lower(i.previousOutpoint.transactionId)}:${Number(i.previousOutpoint.index)}`), [`${f.X}:${f.vaultOut.index}`], `${tag}: the outside payment spends exactly A's T1 successor`);
  return { ...f, t1Pred, t1Entry, spend };
}
/* a reorganization reverses the outside payment: its outputs leave the UTXO table and A's T1 successor comes back exactly */
function reorgReversesPayment(x, f) {
  f.spend.build.frozen.outputs.forEach((_, i) => x.node.spendOutpoint({ transactionId: f.spend.txId, index: i }));
  x.node.putEntry(f.t1Entry.address, f.t1Entry.entry);
}
async function upgradeBefore(x, f) {
  const a = await x.rootReq(f.A);
  assert.equal(a.outOfBandAttribution?.mode, "PARTIAL", "precondition: A carries the PARTIAL marker");
  return { t1: await x.vault(ctx.T1), t1Json: await x.recordJson("VAULT", ctx.T1), rootJson: await x.recordJson("ORG_ROOT", ctx.rootId), t2Json: await x.recordJson("VAULT", ctx.T2), marker: structuredClone(a.outOfBandAttribution) };
}
const OVERCLAIM = /\b(recovered|restored|repaired|fixed|resolved)\b/i;
/* The writer decision 'PARTIAL upgrade': after a PARTIAL attribution, a later Verify that FRESHLY observes A's T1
 * successor output exact and unspent at depth >= 1,000 advances T1 to A's successor with A's registry, records mode FULL
 * with the upgrade on A's marker, and T1 is no longer UNRESOLVED; the answer never claims more than that evidence. */
async function assertUpgraded(x, f, r, before, label, { replay = false } = {}) {
  const t1 = await x.vault(ctx.T1);
  assert.ok(sameOp(t1.live.outpoint, f.vaultOut), `${label}: T1 is advanced to A's treasury successor (recorded at ${t1.live.outpoint.transactionId}:${t1.live.outpoint.index})`);
  assert.deepEqual(await t1Registry(x), f.recA.newRegistry, `${label}: T1 installs A's registry`);
  assert.equal(lower(t1.latestTransitionTxId), f.X, `${label}: T1's last transition is A's transaction`);
  assert.equal(Number(t1.generation ?? 0), Number(before.t1.generation ?? 0) + 1, `${label}: exactly one T1 generation`);
  assert.ok(x.node.entryAt(t1.live.outpoint), `${label}: T1 is recorded at an output the node reports unspent`);
  const a = await x.rootReq(f.A);
  assert.equal(a.state, "CHAIN_VERIFIED", `${label}: A stays CHAIN_VERIFIED`);
  assert.equal(a.finalTransaction, undefined, `${label}: no final transaction is invented`);
  const m = a.outOfBandAttribution;
  assert.ok(m && wr7().boundAttributionMarker(a) !== null, `${label}: A's marker still binds (${JSON.stringify(m)})`);
  assert.equal(m.mode, "FULL", `${label}: the marker records mode FULL`);
  assert.equal(m.treasury.state, "ADVANCED", `${label}: the marker records T1 ADVANCED`);
  for (const k of ["schema", "via", "txId", "requestId", "requiredDepthDaa"]) assert.equal(m[k], before.marker[k], `${label}: the marker's ${k} is unchanged`);
  assert.equal(m.treasury.vaultId, ctx.T1);
  assert.ok(sameOp(m.treasury.predecessorOutpoint, before.marker.treasury.predecessorOutpoint), `${label}: the marker still names T1's predecessor`);
  const recorded = (typeof m.modeChangedAt === "string" && m.modeChangedAt.length > 0 && m.modeChangedAt !== before.marker.modeChangedAt) || (typeof m.upgradedAt === "string" && m.upgradedAt.length > 0) || (m.upgrade && typeof m.upgrade === "object");
  assert.ok(recorded, `${label}: the marker records the upgrade (a new modeChangedAt, or an upgrade record): ${JSON.stringify(m)}`);
  assert.equal(await wr7().treasuryUnresolved(x.config, t1), null, `${label}: T1 is no longer UNRESOLVED`);
  /* the answer: the root did not move in this Verify, so it is not ADVANCED; T1 is answered as what was observed. A Verify
   * that finishes an interrupted upgrade may answer through discovery's attribution replay (addendum a item 5) — then
   * ADVANCED via attribution, mode FULL, naming exactly A and its transaction. */
  if (replay && r.root.status === "ADVANCED") {
    assert.equal(r.root.via, "attribution", `${label}: a replay answer is the attribution answer`);
    assert.equal(r.root.requestId, f.A, `${label}: the replay answer names A`);
    assert.equal(lower(r.root.txId), f.X, `${label}: the replay answer names A's transaction`);
  } else {
    assert.equal(r.root.status, "CONSISTENT", `${label}: the root answer claims no root move (${r.root.status} ${r.root.via ?? ""})`);
  }
  if (r.root.mode !== undefined) assert.equal(r.root.mode, "FULL", `${label}: a mode in the answer is FULL`);
  if (r.root.treasury !== undefined) assert.deepEqual(r.root.treasury, { vaultId: ctx.T1, state: "ADVANCED" }, `${label}: a treasury in the answer is T1 ADVANCED`);
  if (Array.isArray(r.root.holds)) assert.ok(!r.root.holds.some((h) => h && h.scope === ctx.T1), `${label}: no hold names T1 (${JSON.stringify(r.root.holds)})`);
  if (r.root.buildable && r.root.buildable.root === true) assert.ok(r.root.buildable.treasuries.includes(ctx.T1), `${label}: T1 is buildable when the root is`);
  const v = X_.vaultResult(r, ctx.T1);
  assert.ok(v && ["CONSISTENT", "ADVANCED"].includes(v.status), `${label}: T1 is answered as observed at A's successor (${JSON.stringify(v)})`);
  assert.doesNotMatch(String(v.reason ?? ""), /UNRESOLVED/, `${label}: T1 is no longer answered UNRESOLVED`);
  assert.doesNotMatch(JSON.stringify({ root: r.root, t1: v }), OVERCLAIM, `${label}: the answer never says recovered / restored / repaired / fixed / resolved`);
}
/* while A's T1 successor is absent, contradictory or below depth: nothing written (checked by the caller), T1 UNRESOLVED,
 * and the answer claims no upgrade */
async function assertStillUnresolved(x, f, r, before, label, { t1Result = true } = {}) {
  assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, `${label}: T1's record is unchanged`);
  assert.deepEqual((await x.rootReq(f.A)).outOfBandAttribution, before.marker, `${label}: A's PARTIAL marker is unchanged`);
  assert.ok(await wr7().treasuryUnresolved(x.config, await x.vault(ctx.T1)), `${label}: T1 stays UNRESOLVED`);
  assert.notEqual(r.root.status, "ADVANCED", `${label}: no ADVANCED answer`);
  assert.notEqual(r.root.mode, "FULL", `${label}: no FULL answer`);
  if (r.root.treasury !== undefined) assert.equal(r.root.treasury.state, "UNRESOLVED", `${label}: a treasury in the answer stays UNRESOLVED`);
  if (t1Result) assert.ok(!["CONSISTENT", "ADVANCED"].includes(X_.vaultResult(r, ctx.T1)?.status), `${label}: T1 is not answered as advanced or consistent (${JSON.stringify(X_.vaultResult(r, ctx.T1))})`);
}

/* ---- RC45 C4-03c (tests only): legs for the C4-03b item-check findings F-01 (crash safety of the upgrade once the root
 * moved on and the restored output is spent again), F-02 and F-03 (each upgrade rule isolated, after the item check's
 * probe shapes PB1-PB9), F-05 (the replay answer after the upgrade's crash window with the root moved on) and F-07 (the
 * upgrade's event line). Their labels name the C4-03b head: [RED on b387ff0] fails there for the stated reason; [PIN:
 * holds on b387ff0] passes there and must keep passing. ---- */
/* the upgrade's first durable write: A's marker saved with mode FULL */
const upgradeMarkerSave = (f) => (op) => op.category === C().ORG_ROOT_REQUEST && op.key === f.A && op.value?.outOfBandAttribution?.mode === "FULL";
/* A attributed PARTIAL by a first Verify (the outside payment from T1's new output kept reversible); with rootMovesOn the
 * root then moves on through a hosted T2 AUTHORIZE + pause, which spends A's root successor (the UPG-02 shape) */
async function attributedPartial(x, tag, { rootMovesOn = false } = {}) {
  const f = await partialCase(x, tag);
  X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL", label: `${tag}: the PARTIAL attribution` });
  if (rootMovesOn) {
    await X_.ops.pause(x, ctx.T2, `${tag}-pz2`);
    assert.equal(x.node.entryAt(f.rootOut), null, `${tag}: precondition: the root moved on (A's root successor is spent by the hosted T2 AUTHORIZE + pause)`);
  }
  return f;
}
/* the reorganization of reorgReversesPayment, keeping the payment's own entries so that it can be accepted again */
function reversePaymentKeeping(x, f) {
  f.paymentEntries = f.spend.build.frozen.outputs.map((_, i) => x.node.entryAt({ transactionId: f.spend.txId, index: i })).filter(Boolean);
  assert.ok(f.paymentEntries.length > 0, "the outside payment's outputs are on the mock chain before the reorganization");
  reorgReversesPayment(x, f);
}
/* the reversed payment is accepted again: A's restored T1 successor is spent once more and the payment's outputs are back */
function paymentAcceptedAgain(x, f) {
  x.node.spendOutpoint(f.vaultOut);
  for (const e of f.paymentEntries) x.node.putEntry(e.address, e.entry);
  assert.equal(x.node.entryAt(f.vaultOut), null, "A's T1 successor is spent again");
}
/* the replay answer's claim that the root (with or without the treasury) follows A's successor(s) */
const ROOT_FOLLOWS = /\bthe root (?:and treasury \S+ )?follows?\b/i;
const auditLines = async (x) => (await x.store.readAudit({ limit: 5000 })).map((e) => JSON.stringify(e));
/* the event lines present now and not before (as a multiset of their JSON) */
function addedLines(beforeLines, afterLines) {
  const left = new Map();
  for (const s of beforeLines) left.set(s, (left.get(s) ?? 0) + 1);
  const added = [];
  for (const s of afterLines) { const n = left.get(s) ?? 0; if (n > 0) left.set(s, n - 1); else added.push(JSON.parse(s)); }
  return added;
}

/* ---- RC45 C4-08a (tests only): isolating legs for two C4 sabotage-gate survivors on f267cca, SAB04-F02 (CF-U18: the
 * upgrade's failed T1 write swallowed) and SAB04-F01 (N07: the transaction id recomputed from A's frozen bytes dropped
 * from the attributed binding). Their labels name the C4 head: [PIN: holds on f267cca] passes there and must keep
 * passing. ---- */
/* A single store write fault: exactly the first write matching `pred` after a performed write matching `after` fails,
 * once; every other mutation (every other write, the event-line append, createExclusive, remove) is performed. UPG-09's
 * storeFaults fails every mutation after its trigger, so there the upgrade's event-line append fails as well and that
 * later failure masks a swallowed T1 write failure; this fault fails the T1 write alone. */
function singleWriteFault(x, { after, pred }) {
  const s = x.store;
  assert.ok(!Object.prototype.hasOwnProperty.call(s, "write"), "singleWriteFault: the store's write is not already wrapped");
  const original = Object.getPrototypeOf(s).write, failed = [];
  let armed = false;
  s.write = async function singleFault(...args) {
    const op = { kind: "write", category: args[0], key: args[1], value: args[2] };
    if (armed && failed.length === 0 && pred(op)) {
      failed.push(op);
      throw Object.assign(new Error(`TEST transient: one store write failed (${op.category} ${op.key})`), { code: "TEST_TRANSIENT" });
    }
    const out = await original.apply(s, args);
    if (after(op)) armed = true;
    return out;
  };
  return { failures: () => failed.length, restore() { delete s.write; } };
}
/* the upgrade's event line (C4-03d): the treasury follows the attributed output */
const isUpgradeLine = (e) => !!e && (e.action === "attributionUpgrade" || e.result === "TREASURY_FOLLOWS_ATTRIBUTED_OUTPUT");
/* A's records claim another transaction id `y`: its own, its build's, its manifest transaction's and, when it carries one,
 * its marker's, with the manifest hash recomputed so that the manifest still verifies; A's frozen bytes, frozen canonical
 * JSON, root input and registry stay intact (the C4-02 item check's R7 'rehashed' damage). Returns the stored record. */
function rewriteTxIds(x, id, y) {
  return x.editRootReq(id, (q) => {
    q.txId = y;
    q.build.txId = y;
    q.manifest.transaction.txId = y;
    if (q.outOfBandAttribution) q.outOfBandAttribution.txId = y;
    const { manifestHash, ...body } = q.manifest;
    assert.equal(typeof manifestHash, "string", "A's manifest carries its hash");
    q.manifest.manifestHash = require("../../core/intent/canonical").computeManifestHashV1(body);
  });
}
/* the node reports each of A's outputs exactly as accepted (address, value, covenant id, script, accepting DAA) under the
 * transaction id `y` instead of A's own, so that the attribution observes `y` and reaches the binding (with nothing
 * reported under the rewritten id the answer is NO_CANDIDATE, before any binding) */
function outputsUnder(x, f, y) {
  const n = f.recA.build.frozen.outputs.length;
  for (let i = 0; i < n; i++) {
    const e = x.node.entryAt({ transactionId: f.X, index: i });
    assert.ok(e, `A's output ${i} is on the mock chain`);
    x.node.spendOutpoint({ transactionId: f.X, index: i });
    x.node.putEntry(e.address, { ...e.entry, outpoint: { transactionId: y, index: i } });
  }
}
/* ATR-06b / ATR-06c: A withdrawn, the owners rebuild the change as B and sign it (B AUTHORIZED holds the root's
 * reservation), A confirmed outside PolicyVault; with `replay`, a crash right after the attribution's first durable write
 * (A's FULL marker) leaves A RECONCILIATION_REQUIRED with a bound marker. Then A's records claim another id `y` and the
 * Verify at depth refuses at the binding: UNKNOWN RECORD_DAMAGED naming A and `y`; nothing is written, B is not settled
 * and keeps its reservation. */
async function txIdRewritten(x, tag, { replay }) {
  let bId = null;
  const f = await X_.caseFive(x, tag, {
    beforeConfirm: async () => {
      await withAnchor(STALE, async () => {
        const b = await X_.vaultOp(x, ctx.T1, "ownerSetAgentRoot", "authorize", `${tag}-b`, { agents: [ctx.A_, ctx.B_, X_.row(ctx.w.n1, STALE)] });
        assert.equal(b.status, 201, `B is built (${said(b)})`);
        bId = b.body.request.id;
        await X_.sign(x, bId, [1, 2]);
      });
      assert.equal((await X_.rootRec(x)).pendingRequestId, bId, "precondition: B holds the reservation");
    }
  });
  if (replay) {
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === f.A && op.value?.outOfBandAttribution?.mode === "FULL");
    await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, "precondition: the Verify reached A's FULL marker save (the crash is injected right after it)");
    const a = await x.rootReq(f.A);
    assert.equal(a.state, "RECONCILIATION_REQUIRED", "precondition: A is RECONCILIATION_REQUIRED");
    assert.notEqual(wr7().boundAttributionMarker(a), null, "precondition: A carries a bound marker");
    assert.equal((await x.rootReq(bId)).state, "AUTHORIZED", "precondition: B is not settled");
    assert.equal((await X_.rootRec(x)).pendingRequestId, bId, "precondition: B still holds the reservation");
  }
  const aState = (await x.rootReq(f.A)).state;
  const y = K.hex(`rc45-c408a-${tag}-other-txid`);
  assert.notEqual(y, f.X, "the other id is not A's");
  const q = await rewriteTxIds(x, f.A, y);
  if (replay) assert.notEqual(wr7().boundAttributionMarker(q), null, "the rewritten marker still binds (so the replay reaches the binding)");
  outputsUnder(x, f, y);
  const label = `${replay ? "replay" : "fresh"}: A's own, build and manifest${replay ? " and marker" : ""} transaction ids rewritten to another id (frozen bytes intact, manifest hash recomputed)`;
  const r = await writesNothing(x, label, () => X_.verify(x));
  X_.assertUnknown(r, label);
  X_.assertAttributionOutcome(r, "RECORD_DAMAGED", { requestId: f.A, label });
  assert.equal(lower(r.root.attribution.txId ?? ""), y, `${label}: the refusal names the rewritten id (the binding was reached)`);
  const b = await x.rootReq(bId);
  assert.equal(b.state, "AUTHORIZED", `${label}: no settlement (B stays AUTHORIZED)`);
  assert.ok(b.submissionOutcome == null, `${label}: B carries no outcome (${JSON.stringify(b.submissionOutcome)})`);
  const root = await X_.rootRec(x);
  assert.equal(root.pendingRequestId, bId, `${label}: no hold release (B keeps the root's reservation)`);
  assert.ok(sameOp(root.live.outpoint, f.P), `${label}: the root record still names P`);
  assert.equal((await x.rootReq(f.A)).state, aState, `${label}: A's state is unchanged`);
  assert.ok((await X_.receiptOf(x, y)) == null, `${label}: no receipt for the rewritten id`);
  assert.ok((await X_.receiptOf(x, f.X)) == null, `${label}: no receipt for A's own id`);
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", X_.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 L2-01 ${backend}: ${name}`, { skip }, async () => { const x = await X_.fresh(backend); try { await fn(x); } finally { await X_.release(x); } });

  /* =============================== ATR: attribution and completion =============================== */
  leg("ATR-01 FULL, two treasuries: a stale delegate-rule change A on T1, withdrawn and confirmed outside PolicyVault; the first Verify at depth 1,000 answers ADVANCED via attribution (FULL): the root and T1 follow A's successor (T1 installs A's registry), T2 stays byte-identical, nothing holds the root (buildable.root true); then FREEZE (K) + emergency pause and UNFREEZE (M) on T1 and on T2, T2 AUTHORIZE + pause and a root FREEZE each reach CHAIN_VERIFIED [RED on 8877dee]", async (x) => {
    const t2Before = await x.recordJson("VAULT", ctx.T2);
    const f = await X_.caseFive(x, "atr01");
    const rootBefore = await X_.rootRec(x), t1Before = await x.vault(ctx.T1);
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "FULL" });
    assert.deepEqual(r.root.holds, [], "no request or state holds the root or a treasury");
    assert.equal(r.root.buildable.root, true, "the root is buildable");
    assert.deepEqual([...r.root.buildable.treasuries].sort(), [ctx.T1, ctx.T2].sort(), "both treasuries are buildable (FULL)");
    await X_.assertMarker(x, f, { mode: "FULL" });
    await X_.assertCompletedOnce(x, f);
    const root = await X_.rootRec(x);
    assert.ok(sameOp(root.live.outpoint, f.rootOut), "the root record follows A's root successor");
    assert.equal(root.pendingRequestId, null, "the root holds no reservation");
    assert.equal(Number(root.generation ?? 0), Number(rootBefore.generation ?? 0) + 1, "exactly one root generation");
    const t1 = await x.vault(ctx.T1);
    assert.ok(sameOp(t1.live.outpoint, f.vaultOut), "T1 follows A's treasury successor");
    assert.deepEqual(await t1Registry(x), f.recA.newRegistry, "T1 installs A's registry");
    assert.equal(lower(t1.latestTransitionTxId), f.X);
    assert.equal(Number(t1.generation ?? 0), Number(t1Before.generation ?? 0) + 1, "exactly one T1 generation");
    assert.equal(await x.recordJson("VAULT", ctx.T2), t2Before, "T2 is byte-identical");
    assert.equal(X_.vaultResult(r, ctx.T1)?.status, "CONSISTENT", "T1 reads back consistent at A's successor");
    await X_.ops.emergencyPause(x, ctx.T1, "atr01-ep1");
    await X_.ops.unfreeze(x, "atr01-uf1");
    await X_.ops.emergencyPause(x, ctx.T2, "atr01-ep2");
    await X_.ops.unfreeze(x, "atr01-uf2");
    await X_.ops.unpause(x, ctx.T2, "atr01-up2");
    await X_.ops.pause(x, ctx.T2, "atr01-pz2");
    await X_.ops.rootFreeze(x, "atr01-fz");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing is left holding the root");
  });

  leg("ATR-02 A AUTHORIZED and stale (never withdrawn) holds the root's reservation; confirmed outside PolicyVault, the Verify at depth attributes it (ADVANCED FULL), releases A's own reservation, holds is empty, and a root FREEZE reaches CHAIN_VERIFIED [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "atr02", { withdraw: false });
    assert.equal((await X_.rootRec(x)).pendingRequestId, f.A, "precondition: A (AUTHORIZED, stale) holds the root's reservation");
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    assert.deepEqual(r.root.holds, []);
    assert.equal(r.root.buildable.root, true);
    await X_.assertMarker(x, f);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "A's own reservation is released");
    await X_.ops.rootFreeze(x, "atr02-fz");
  });

  leg("ATR-03 A withdrawn (REFUSED), the owners rebuild the change as B and sign it (B AUTHORIZED holds the reservation); A is confirmed outside PolicyVault: the Verify at depth attributes A, settles B SUPERSEDED with the attribution proof in one save, clears the reservation, holds is empty, and a new delegate-rule change builds from A's successor [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "atr03", {
      beforeConfirm: async () => {
        await withAnchor(STALE, async () => {
          const b = await X_.vaultOp(x, ctx.T1, "ownerSetAgentRoot", "authorize", "atr03-b", { agents: [ctx.A_, ctx.B_, X_.row(ctx.w.n1, STALE)] });
          assert.equal(b.status, 201, `B is built (${said(b)})`);
          bId = b.body.request.id;
          await X_.sign(x, bId, [1, 2]);
        });
        assert.equal((await X_.rootRec(x)).pendingRequestId, bId, "precondition: B holds the reservation");
      }
    });
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    const b = await x.rootReq(bId);
    assert.equal(b.state, "SUPERSEDED", "B is settled SUPERSEDED");
    assert.equal(b.submissionOutcome?.outcome, "SUPERSEDED");
    assert.equal(b.submissionOutcome.proof?.via, "attribution");
    assert.equal(lower(b.submissionOutcome.proof.acceptedConflictingTxId), f.X);
    assert.equal(b.submissionOutcome.proof.attributedRequestId, f.A);
    assert.ok(sameOp(b.submissionOutcome.proof.spentOutpoint, f.P), "the proof names the spent root outpoint P");
    assert.ok(JSON.stringify(r.root.settled).includes(bId), "the answer lists B as settled");
    assert.deepEqual(r.root.holds, []);
    assert.equal(r.root.buildable.root, true);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "the reservation is cleared");
    await withAnchor(STALE + DEPTH, async () => {
      const n = await X_.vaultOp(x, ctx.T1, "ownerSetAgentRoot", "authorize", "atr03-next", { agents: [...f.recA.newRegistry, X_.row(ctx.w.n2, STALE + DEPTH)] });
      assert.equal(n.status, 201, `a new delegate-rule change builds (${said(n)})`);
      assert.ok(sameOp(n.body.request.manifest.root.outpoint, f.rootOut), "it is built on A's root successor");
    });
  });

  leg("ATR-04 depth boundary: at depth 999 Verify answers UNKNOWN BELOW_DEPTH (depthDaa 999, requiredDepthDaa 1000) and writes nothing, and a root build is refused 409 RECORDED_OUTPUT_SPENT writing nothing; one DAA later the Verify answers ADVANCED at depth 1,000 [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "atr04", { depth: DEPTH - 1n });
    const r1 = await writesNothing(x, "Verify at depth 999", () => X_.verify(x));
    X_.assertUnknown(r1, "depth 999");
    X_.assertAttributionOutcome(r1, "BELOW_DEPTH", { requestId: f.A, label: "depth 999" });
    assert.equal(String(r1.root.attribution.depthDaa), "999");
    await refused(x, "a root FREEZE below depth", () => X_.rootOnly(x, "freeze", "atr04-fz"), 409, "RECORDED_OUTPUT_SPENT");
    x.node.state.daa += 1n;
    const r2 = await X_.verify(x);
    X_.assertAttributedAdvanced(r2, f, { depth: "1000" });
  });

  leg("ATR-05 PARTIAL: a delegate of A pays from T1's new output outside PolicyVault before any Verify; the Verify at depth answers ADVANCED via attribution, mode PARTIAL, treasury T1 UNRESOLVED; T1's record is byte-identical, the marker records T1 UNRESOLVED, holds names exactly T1's UNRESOLVED state, buildable.root is true and only T2 is a buildable treasury [RED on 8877dee]", async (x) => {
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    const f = await X_.caseFive(x, "atr05", { mode: "PARTIAL" });
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1's record is never written in PARTIAL");
    const a = await X_.assertMarker(x, f, { mode: "PARTIAL" });
    assert.equal(a.chain?.completion?.vault, "UNRESOLVED", "A's completion records the vault side UNRESOLVED");
    assert.deepEqual(r.root.holds, [{ scope: ctx.T1, reason: "UNRESOLVED", requestId: f.A, txId: f.X }], "holds names T1's UNRESOLVED state");
    assert.equal(r.root.buildable.root, true);
    assert.deepEqual(r.root.buildable.treasuries, [ctx.T2], "T1 is never listed buildable in PARTIAL");
    const root = await X_.rootRec(x);
    assert.ok(sameOp(root.live.outpoint, f.rootOut), "the root record follows A's root successor");
    assert.equal(root.pendingRequestId, null);
    await X_.assertCompletedOnce(x, f);
  });

  leg("ATR-06 record damage: with A's frozen bytes, its stored registry, its manifest transaction id or frozen canonical JSON edited, or A's root input not the recorded root outpoint, the Verify at depth answers UNKNOWN RECORD_DAMAGED and writes nothing [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "atr06");
    const original = await x.store.read(C().ORG_ROOT_REQUEST, f.A), rootOriginal = await x.store.read(C().ORG_ROOT, ctx.rootId);
    const forged = { transactionId: K.hex("rc45-l201-atr06-other-root-outpoint"), index: 0 };
    const variants = [
      ["A's frozen bytes (its last output's value)", () => x.editRootReq(f.A, (q) => { const o = q.build.frozen.outputs; o[o.length - 1].value = (BigInt(o[o.length - 1].value) - 1n).toString(); })],
      ["A's stored registry", () => x.editRootReq(f.A, (q) => { q.newRegistry[0].maxPerSpend = (BigInt(q.newRegistry[0].maxPerSpend) + 1n).toString(); })],
      ["A's manifest transaction id", () => x.editRootReq(f.A, (q) => { q.manifest.transaction.txId = K.hex("rc45-l201-atr06-forged-txid"); })],
      ["A's manifest frozen canonical JSON", () => x.editRootReq(f.A, (q) => { const j = JSON.parse(q.manifest.transaction.frozenCanonicalJson); const o = j.outputs[j.outputs.length - 1]; o.value = (BigInt(o.value) - 1n).toString(); q.manifest.transaction.frozenCanonicalJson = JSON.stringify(j); })],
      ["A's root input is not the recorded root outpoint", async () => {
        await x.editRootReq(f.A, (q) => { q.manifest.root.outpoint = { ...forged }; });
        const root = await x.store.read(C().ORG_ROOT, ctx.rootId);
        root.live = { ...root.live, outpoint: { ...forged } };
        await x.store.write(C().ORG_ROOT, ctx.rootId, root);
      }]
    ];
    for (const [label, edit] of variants) {
      await edit();
      const r = await writesNothing(x, label, () => X_.verify(x));
      X_.assertUnknown(r, label);
      X_.assertAttributionOutcome(r, "RECORD_DAMAGED", { label });
      await x.store.write(C().ORG_ROOT_REQUEST, f.A, original);
      await x.store.write(C().ORG_ROOT, ctx.rootId, rootOriginal);
    }
  });

  /* RC45 C4-08a (SAB04-F01, N07): ATR-06's damages each fail a check other than the txid recomputation; here only that
   * recomputation can refuse */
  leg("ATR-06b (record damage: the transaction id recomputed from the frozen bytes) A's own, build and manifest transaction ids all rewritten to another id with the manifest hash recomputed (A's frozen bytes, frozen canonical JSON, root input and registry intact; the node reports A's outputs, exactly as accepted, under that id), B holding the root's reservation: the Verify at depth answers UNKNOWN RECORD_DAMAGED naming A and that id and writes nothing: no settlement (B stays AUTHORIZED), no hold release (B keeps the reservation), no record, receipt or event line [PIN: holds on f267cca]", async (x) => {
    await txIdRewritten(x, "atr06b", { replay: false });
  });

  leg("ATR-06c (record damage on a replay: the transaction id recomputed from the frozen bytes) a crash right after A's FULL marker save leaves A RECONCILIATION_REQUIRED with a bound marker; A's own, build, manifest and marker transaction ids all rewritten to another id with the manifest hash recomputed (A's frozen bytes intact, the marker still binds; the node reports A's outputs under that id), B holding the root's reservation: the Verify at depth answers UNKNOWN RECORD_DAMAGED naming A and that id and writes nothing: no settlement, no hold release, no record, receipt or event line [PIN: holds on f267cca]", async (x) => {
    await txIdRewritten(x, "atr06c", { replay: true });
  });

  leg("ATR-07 out of scope: a root-only FREEZE carrying its owner quorum (AUTHORIZED), confirmed outside PolicyVault, answers UNKNOWN NOT_IN_SCOPE naming it and writes nothing; the ordinary path re-attaches it: Finalize, Submit (the node answers orphan) -> RECONCILIATION_REQUIRED, Verify -> ADVANCED and the request CHAIN_VERIFIED [RED on 8877dee]", async (x) => {
    const b = await X_.rootOnly(x, "freeze", "atr07-f");
    assert.equal(b.status, 201, said(b));
    const id = b.body.request.id;
    await X_.sign(x, id, [1]);
    const q = await x.rootReq(id);
    assert.equal(q.state, "AUTHORIZED");
    KK.seedFee(x, q);
    KK.confirmOutOfBand(x, q);
    x.node.state.daa += DEPTH;
    const r1 = await writesNothing(x, "Verify of an out-of-scope request", () => X_.verify(x));
    X_.assertUnknown(r1, "out of scope");
    X_.assertAttributionOutcome(r1, "NOT_IN_SCOPE", { requestId: id, label: "out of scope" });
    const fin = await x.rootFinalize(ctx.rootId, id);
    assert.equal(fin.status, 200, `Finalize (${said(fin)})`);
    assert.equal(fin.body.request.state, "SIGNED");
    const sub = await KK.NODE().with(KK.outcomeRpc(x, { submitAnswer: "orphan" }), () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "submit"], {}, x.cookie.o1));
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `Submit (${said(sub)})`);
    const r2 = await X_.verify(x);
    assert.equal(r2.root.status, "ADVANCED", `the claim path re-attaches it (${r2.root.reason ?? ""})`);
    assert.equal((await x.rootReq(id)).state, "CHAIN_VERIFIED");
  });

  /* =============================== UNR: PARTIAL and the UNRESOLVED treasury =============================== */
  leg("UNR-01 PARTIAL: every hosted T1 action is refused 409 TREASURY_STATE_UNRESOLVED naming A and its txid, writing nothing — FREEZE (K) + emergency pause, AUTHORIZE + pause, close and recover, a delegate build, the delegate signature of a BUILT request and the broadcast of a SIGNED one; with the root held by another request the T1 owner action answers ROOT_PENDING_REQUEST first; T1 stays byte-identical [RED on 8877dee]", async (x) => {
    const db = await X_.delegateBuild(x, ctx.T1);
    assert.equal(db.status, 201, `a delegate request built before A (${said(db)})`);
    const dbId = db.body.request.requestId;
    const ds = await X_.delegateBuild(x, ctx.T1, { payKas: 2n });
    assert.equal(ds.status, 201, said(ds));
    const dsId = ds.body.request.requestId;
    const dsSigned = await X_.delegateSign(x, dsId);
    assert.equal(dsSigned.status, 200, `a SIGNED delegate request before A (${said(dsSigned)})`);
    const f = await X_.caseFive(x, "unr01", { mode: "PARTIAL" });
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    const unresolved = async (label, call) => {
      const res = await refused(x, label, call, 409, "TREASURY_STATE_UNRESOLVED");
      assert.ok(String(res.message).includes(f.A), `${label}: names A`);
      assert.ok(lower(res.message).includes(f.X), `${label}: names A's txid`);
    };
    await unresolved("T1 FREEZE (K) + emergency pause", () => X_.vaultOp(x, ctx.T1, "ownerEmergencyPause", "freeze", "unr01-ep"));
    await unresolved("T1 AUTHORIZE + pause", () => X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "unr01-pz"));
    await unresolved("T1 close and recover", () => X_.vaultOp(x, ctx.T1, "ownerRecover", "authorize", "unr01-rc"));
    await unresolved("a T1 delegate build", () => X_.delegateBuild(x, ctx.T1));
    await unresolved("the delegate signature of a BUILT T1 request", () => X_.delegateSign(x, dbId));
    const dsRec = await x.kasReq(dsId);
    await unresolved("the broadcast of a SIGNED T1 delegate request", () => X_.delegateSubmitWith(x, dsId, KK.outcomeRpc(x, { submitAnswer: "strict", frozen: dsRec.build.frozen })));
    const hold = await X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", "unr01-hold");
    assert.equal(hold.status, 201, `another request holds the root (${said(hold)})`);
    await refused(x, "a T1 owner action while the root is held", () => X_.vaultOp(x, ctx.T1, "ownerEmergencyPause", "freeze", "unr01-ep-held"), 409, "ROOT_PENDING_REQUEST");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is byte-identical");
  });

  leg("UNR-01 (paused record) PARTIAL with T1 PAUSED in its record: a delegate build and an owner unpause on T1 answer 409 TREASURY_STATE_UNRESOLVED, not VAULT_PAUSED, writing nothing [RED on 8877dee]", async (x) => {
    await X_.ops.pause(x, ctx.T1, "unr01p-pz");
    const t1Paused = await x.vault(ctx.T1);
    assert.equal(t1Paused.status, "PAUSED", "precondition: T1 is PAUSED in its record");
    const f = await X_.caseFive(x, "unr01p", { beforeConfirm: null });
    x.node.spendOutpoint(f.vaultOut); // T1's new output spent outside PolicyVault
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    for (const [label, call] of [["a T1 delegate build", () => X_.delegateBuild(x, ctx.T1)], ["a T1 owner unpause", () => X_.vaultOp(x, ctx.T1, "ownerUnpause", "authorize", "unr01p-up")]]) {
      const res = await refused(x, label, call, 409, "TREASURY_STATE_UNRESOLVED");
      assert.ok(String(res.message).includes(f.A), `${label}: names A`);
    }
  });

  leg("UNR-02 PARTIAL: the root and the other treasury recover independently — root FREEZE, UNFREEZE, T2 FREEZE (K) + emergency pause, UNFREEZE, T2 AUTHORIZE + unpause and AUTHORIZE + pause each reach CHAIN_VERIFIED; T1 stays byte-identical [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "unr02", { mode: "PARTIAL" });
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    await X_.ops.rootFreeze(x, "unr02-fz");
    await X_.ops.unfreeze(x, "unr02-uf1");
    await X_.ops.emergencyPause(x, ctx.T2, "unr02-ep2");
    await X_.ops.unfreeze(x, "unr02-uf2");
    await X_.ops.unpause(x, ctx.T2, "unr02-up2");
    await X_.ops.pause(x, ctx.T2, "unr02-pz2");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is byte-identical");
  });

  leg("UNR-03 PARTIAL: Verify's T1 result and reconcileKasVault both answer UNKNOWN naming T1's UNRESOLVED state [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "unr03", { mode: "PARTIAL" });
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    const v = X_.vaultResult(r, ctx.T1);
    assert.equal(v?.status, "UNKNOWN");
    assert.match(String(v.reason), /UNRESOLVED/, `Verify names the unresolved state (${v.reason})`);
    const direct = await KK.lazy.wr7kas.reconcileKasVault(x.config, x.node.rpc, ctx.T1, { stalePendingMinimumMs: 0 });
    assert.equal(direct.status, "UNKNOWN");
    assert.match(String(direct.reason), /UNRESOLVED/, `reconcileKasVault names the unresolved state (${direct.reason})`);
  });

  leg("UNR-05 PARTIAL: a later Verify answers the root CONSISTENT and T1 UNRESOLVED, writes nothing and never replays A again (no loop) [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "unr05", { mode: "PARTIAL" });
    const r1 = await X_.verify(x);
    X_.assertAttributedAdvanced(r1, f, { mode: "PARTIAL" });
    const aJson = await x.recordJson("ORG_ROOT_REQUEST", f.A);
    const r2 = await writesNothing(x, "the later Verify", () => X_.verify(x));
    assert.equal(r2.root.status, "CONSISTENT", `the root reads back consistent (${r2.root.status})`);
    assert.match(String(X_.vaultResult(r2, ctx.T1)?.reason), /UNRESOLVED/);
    assert.equal(await x.recordJson("ORG_ROOT_REQUEST", f.A), aJson, "A is not replayed");
  });

  /* =============================== CTR: contradictory observations (nothing written) =============================== */
  leg("CTR-01 the root successor is gone on the bracket re-read (spent between the first read and the re-read): UNKNOWN, nothing written; when the answer carries the detail it is UNSTABLE [PIN: holds on 8877dee]", (x) => ctr01(x, DETAIL.PIN));
  leg("CTR-01 (detail) the root successor gone on the bracket re-read: the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome UNSTABLE and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => ctr01(x, DETAIL.RED));

  leg("CTR-02 T1's successor is spent between the two T1 reads: UNKNOWN, nothing written; when the answer carries the detail it is UNSTABLE [PIN: holds on 8877dee]", (x) => ctr02(x, DETAIL.PIN));
  leg("CTR-02 (detail) T1's successor spent between the two T1 reads: the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome UNSTABLE and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => ctr02(x, DETAIL.RED));

  leg("CTR-02 (next Verify) after T1's successor was spent mid-Verify, the next Verify answers ADVANCED PARTIAL [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "ctr02n");
    const t1succ = X_.vaultSuccessorAddress(x, f.recA);
    x.node.afterRead((c) => c.method === "getUtxosByAddresses" && c.addresses.includes(t1succ), 1, () => x.node.spendOutpoint(f.vaultOut));
    const r1 = await writesNothing(x, "T1 successor spent mid-Verify", () => X_.verify(x));
    X_.assertUnknown(r1, "the changing Verify");
    const r2 = await X_.verify(x);
    X_.assertAttributedAdvanced(r2, f, { mode: "PARTIAL" });
  });

  leg("CTR-03 depth 999: UNKNOWN, nothing written; when the answer carries the detail it is BELOW_DEPTH [PIN: holds on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "ctr03", { depth: DEPTH - 1n });
    const r = await writesNothing(x, "Verify at depth 999", () => X_.verify(x));
    X_.assertUnknown(r, "CTR-03");
    X_.ifAttribution(r, "BELOW_DEPTH", "CTR-03");
    void f;
  });

  leg("CTR-03 (exact boundary) depth 999 writes nothing and depth exactly 1,000 attributes (>=, not >) [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "ctr03b", { depth: DEPTH - 1n });
    await writesNothing(x, "Verify at depth 999", () => X_.verify(x));
    x.node.state.daa += 1n;
    X_.assertAttributedAdvanced(await X_.verify(x), f, { depth: "1000" });
  });

  leg("CTR-04 a non-exact entry under A's txid (value, covenant id, script, a null script), on the root successor and on T1's successor: UNKNOWN, nothing written; when the answer carries the detail it is CONTRADICTION [PIN: holds on 8877dee]", (x) => ctr04(x, DETAIL.PIN));
  leg("CTR-04 (detail) each non-exact entry under A's txid (value, covenant id, script, a null script; on the root successor and on T1's successor): the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome CONTRADICTION and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => ctr04(x, DETAIL.RED));

  leg("CTR-05 an input of A is still reported unspent (its fee input): UNKNOWN, nothing written; when the answer carries the detail it is CONTRADICTION [PIN: holds on 8877dee]", (x) => ctr05(x, DETAIL.PIN));
  leg("CTR-05 (detail) an input of A still reported unspent (its fee input): the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome CONTRADICTION and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => ctr05(x, DETAIL.RED));

  leg("CTR-06 a non-canonical blockDaaScore on A's root successor entry (hex, negative, fractional, null): UNKNOWN, nothing written; when the answer carries the detail it is OBSERVATION_ERROR [PIN: holds on 8877dee]", (x) => ctr06(x, DETAIL.PIN));
  leg("CTR-06 (detail) each non-canonical blockDaaScore on A's root successor entry (hex, negative, fractional, null): the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome OBSERVATION_ERROR and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => ctr06(x, DETAIL.RED));

  leg("CTR-07 FULL with T1's and the root's entries at different accepting DAA: UNKNOWN, nothing written; when the answer carries the detail it is CONTRADICTION [PIN: holds on 8877dee]", (x) => ctr07(x, DETAIL.PIN));
  leg("CTR-07 (detail) FULL with T1's and the root's entries at different accepting DAA: the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome CONTRADICTION and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => ctr07(x, DETAIL.RED));

  /* C4-03 item check F-01: the only guard against T1's successor being spent after the observation's bracket is the
   * completion's own fresh re-observation (contract D3); the spend is placed after the bracket's T1 read so the bracket
   * (#1 = #2 = EXACT) cannot catch it. */
  leg("CTR-08 (completion re-check) T1's successor is spent AFTER the observation's bracket (its second T1 read answered EXACT) and BEFORE the attributed completion's own fresh re-observation of T1: UNKNOWN UNSTABLE naming A, nothing written — A stays REFUSED (no recordCompletionFailure), no receipt, T1 never adopts the spent output; the next Verify answers ADVANCED PARTIAL with T1 byte-identical [PIN: holds on d79f710]", async (x) => {
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    const f = await X_.caseFive(x, "ctr08");
    const t1succ = X_.vaultSuccessorAddress(x, f.recA);
    assert.notEqual(t1succ, t1InputAddress(x, f.recA), "precondition: A's T1 successor address is not T1's predecessor address (the reads counted below are reads of A's T1 output only)");
    const from = x.node.reads().length;
    let spentAfterReads = null;
    x.node.afterRead(isReadOf(t1succ), 2, () => { spentAfterReads = readsSince(x, t1succ, from); x.node.spendOutpoint(f.vaultOut); });
    const r = await writesNothing(x, "T1 spent between the bracket and the completion's re-observation", () => X_.verify(x));
    assert.equal(spentAfterReads, 2, "the spend lands right after the bracket's T1 read (#2), which answered before it");
    assert.ok(readsSince(x, t1succ, from) >= 3, `the completion re-reads T1's successor after the spend (its own fresh re-observation; ${readsSince(x, t1succ, from)} reads)`);
    X_.assertUnknown(r, "CTR-08");
    X_.assertAttributionOutcome(r, "UNSTABLE", { requestId: f.A, label: "CTR-08" });
    assert.equal((await x.rootReq(f.A)).state, "REFUSED", "A is unchanged (no recordCompletionFailure before the marker)");
    assert.equal(await X_.receiptOf(x, f.X), null, "no receipt for A's txid");
    const r2 = await X_.verify(x);
    X_.assertAttributedAdvanced(r2, f, { mode: "PARTIAL" });
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 never adopted the spent output");
  });

  /* =============================== DUP: duplicate records (GAP-3) =============================== */
  leg("DUP-01 two records carry A's txid (a store clone of A): UNKNOWN, nothing written; when the answer carries the detail it is AMBIGUOUS [PIN: holds on 8877dee]", (x) => dup01(x, DETAIL.PIN));
  leg("DUP-01 (detail) two records carry A's txid: the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome AMBIGUOUS and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => dup01(x, DETAIL.RED));

  leg("DUP-01 (builds) with two records carrying A's txid, a hosted root build is refused 409 RECORDED_OUTPUT_SPENT writing nothing (the root's recorded output is spent) [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "dup01b");
    const clone = structuredClone(await x.store.read(C().ORG_ROOT_REQUEST, f.A));
    clone.id = crypto.randomUUID();
    await x.store.write(C().ORG_ROOT_REQUEST, clone.id, clone);
    X_.assertUnknown(await X_.verify(x), "DUP-01");
    await refused(x, "a root FREEZE while the root's recorded output is spent", () => X_.rootOnly(x, "freeze", "dup01b-fz"), 409, "RECORDED_OUTPUT_SPENT");
  });

  /* =============================== BND: boundaries =============================== */
  leg("BND-01 the owners' own on-chain exit from A's successor (FREEZE (K = 1) + emergency pause on T1, built with existing SDK functions, real VM PASS) confirmed before any Verify: UNKNOWN, records byte-identical, A stays REFUSED with no receipt; when the answer carries the detail it is NO_CANDIDATE [PIN: holds on 8877dee]", (x) => bnd01(x, DETAIL.PIN));
  leg("BND-01 (detail) the owners' own on-chain exit from A's successor confirmed before any Verify: the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome NO_CANDIDATE and requiredDepthDaa 1000, records byte-identical [RED on 8877dee]", (x) => bnd01(x, DETAIL.RED));

  leg("BND-02 the owners' exit AFTER a FULL attribution (from the recorded successors): the next Verify answers exactly the unchanged UNKNOWN ('live outpoint gone, no claim') and writes nothing [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "bnd02");
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    const succ = await KK.successorsOf(x, f.recA, { rootId: ctx.rootId, vaultId: ctx.T1 });
    const ep = KK.offlineOwnerOp(x, { vault: { ...(await x.vault(ctx.T1)) }, root: succ.root, rootId: ctx.rootId, action: "ownerEmergencyPause", signers: [1], tag: "r3n01-bnd02" });
    assert.equal(ep.vm, "PASS");
    x.node.expectFrozen(ep.build.frozen, ep.txId);
    x.node.state.effects.get(ep.txId)();
    x.node.state.daa += 2000n;
    const r = await writesNothing(x, "Verify after the exit", () => X_.verify(x));
    assert.deepEqual(r.root, { status: "UNKNOWN", rootCovenantId: ctx.rootId, reason: "live outpoint gone, no claim" }, "exactly the unchanged UNKNOWN");
  });

  leg("BND-03 a foreign spend of the root's recorded outpoint P (not A's transaction) with A built and withdrawn: UNKNOWN, nothing written; when the answer carries the detail it is NO_CANDIDATE [PIN: holds on 8877dee]", (x) => bnd03(x, DETAIL.PIN));
  leg("BND-03 (detail) a foreign spend of the root's recorded outpoint P with A built and withdrawn: the UNKNOWN answer carries the attribution detail (contract D2.10) with outcome NO_CANDIDATE and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => bnd03(x, DETAIL.RED));

  leg("BND-04 the root's live outpoint gone with NO record candidate: the answer is exactly the unchanged UNKNOWN and the node reads are exactly the unchanged ones (the root and each treasury address once, no DAA read), also when the DAA read would fail [PIN: holds on 8877dee]", async (x) => {
    const root = await X_.rootRec(x);
    const t1 = await x.vault(ctx.T1), t2 = await x.vault(ctx.T2);
    const expected = [root.live.address, x.node.entryAt(t1.live.outpoint).address, x.node.entryAt(t2.live.outpoint).address].sort();
    x.node.spendOutpoint(root.live.outpoint);
    for (const [label, rpc] of [["a working node", x.node.rpc], ["a node whose DAA read fails", { ...x.node.rpc, getBlockDagInfo: async () => { x.node.state.reads.push({ method: "getBlockDagInfo", addresses: null }); throw new Error("TEST node: the DAA read fails"); } }]]) {
      const from = x.node.reads().length;
      const r = await writesNothing(x, label, () => X_.verify(x, { rpc }));
      assert.deepEqual(r.root, { status: "UNKNOWN", rootCovenantId: ctx.rootId, reason: "live outpoint gone, no claim" }, `${label}: exactly the unchanged UNKNOWN`);
      const reads = x.node.reads().slice(from);
      assert.deepEqual(reads.filter((c) => c.method === "getUtxosByAddresses").flatMap((c) => c.addresses).sort(), expected, `${label}: only the unchanged UTXO reads`);
      assert.equal(reads.filter((c) => c.method === "getBlockDagInfo").length, 0, `${label}: no DAA read`);
    }
  });

  /* C4-03 item check F-03: the D1 gate (attribution runs only with claim release allowed) */
  leg("BND-04b (D1 gate) A confirmed outside PolicyVault at depth, Verify with claim release not allowed (allowClaimRelease false): the live-outpoint-gone branch never attributes — exactly the unchanged UNKNOWN, no DAA read, no read of A's root successor address, nothing written; a Verify with claim release then attributes A (ADVANCED FULL) [PIN: holds on d79f710]", async (x) => {
    const f = await X_.caseFive(x, "bnd04b");
    const succ = X_.rootSuccessorAddress(x, f.recA), live = (await X_.rootRec(x)).live.address;
    const from = x.node.reads().length;
    const r = await writesNothing(x, "Verify without claim release", () => X_.verify(x, { allowClaimRelease: false }));
    assert.deepEqual(r.root, { status: "UNKNOWN", rootCovenantId: ctx.rootId, reason: "live outpoint gone, no claim" }, "exactly the unchanged UNKNOWN");
    const reads = x.node.reads().slice(from);
    assert.equal(reads.filter((c) => c.method === "getBlockDagInfo").length, 0, "no DAA read");
    assert.equal(reads.filter(isReadOf(succ)).length, succ === live ? 1 : 0, "no read of A's root successor address beyond the live-outpoint read");
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "FULL" });
  });

  leg("BND-05 a candidate present and a node read inside attribution failing (the DAA read; the read of A's root successor address; the read of T1's successor address): the Verify returns (never throws) UNKNOWN and writes nothing; when the answer carries the detail it is OBSERVATION_ERROR [PIN: holds on 8877dee]", (x) => bnd05(x, DETAIL.PIN));
  leg("BND-05 (detail) a candidate present and a node read inside attribution failing (the DAA read; A's root successor address; T1's successor address): the Verify returns an UNKNOWN answer carrying the attribution detail (contract D2.10) with outcome OBSERVATION_ERROR and requiredDepthDaa 1000, nothing written [RED on 8877dee]", (x) => bnd05(x, DETAIL.RED));

  /* C4-03 item check F-02 (two legs): the attributed completion's own reads and refusals before its first write. Reads of
   * an address before the completion: A's root successor — the live-outpoint read (only when it is the recorded root's
   * address), D2's candidate read, D2's input read of P's address (same condition) and the bracket re-read; T1's
   * successor — D2's reads #1 and #2; A's fee input — D2's input read. */
  leg("BND-05b (completion reads) a node read made by the attributed completion itself fails (its read of A's root successor address; its re-read of T1's successor address; its re-read of A's fee input address): the Verify returns (never throws) UNKNOWN OBSERVATION_ERROR naming A and writes nothing, A stays REFUSED; a Verify on a working node then attributes A (ADVANCED FULL) [PIN: holds on d79f710]", async (x) => {
    const f = await X_.caseFive(x, "bnd05b");
    const succ = X_.rootSuccessorAddress(x, f.recA), live = (await X_.rootRec(x)).live.address, t1succ = X_.vaultSuccessorAddress(x, f.recA);
    const feeInput = f.recA.build.frozen.inputs[f.recA.build.frozen.inputs.length - 1];
    const fee = SC.spkAddress(x.config, feeInput.utxo.scriptPublicKey);
    assert.ok(![succ, live, t1succ, t1InputAddress(x, f.recA)].includes(fee), "precondition: A's fee input address is read only as an input address");
    const failNth = (address, nth) => X_.faultyRpc(x.node.rpc, { method: "getUtxosByAddresses", pred: ({ addresses }) => addresses.map(String).includes(address), nth });
    const variants = [
      ["the completion's read of A's root successor address", failNth(succ, succ === live ? 6 : 3)],
      ["the completion's re-read of T1's successor address", failNth(t1succ, 3)],
      ["the completion's re-read of A's fee input address", failNth(fee, 2)]
    ];
    for (const [label, rpc] of variants) {
      const r = await writesNothing(x, label, () => X_.verify(x, { rpc }));
      X_.assertUnknown(r, label);
      X_.assertAttributionOutcome(r, "OBSERVATION_ERROR", { requestId: f.A, label });
      assert.equal((await x.rootReq(f.A)).state, "REFUSED", `${label}: A is unchanged`);
    }
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "FULL" });
  });

  leg("BND-06 (refusal before the marker) A's root successor is spent AFTER the observation's bracket re-read and BEFORE the attributed completion's own read of it (another spend of A's root output lands mid-Verify): the completion refuses before its first write — the Verify returns (never throws) UNKNOWN COMPLETION_REFUSED naming A, nothing written, A stays REFUSED (no recordCompletionFailure), no receipt; the next Verify answers UNKNOWN NO_CANDIDATE, writing nothing [PIN: holds on d79f710]", async (x) => {
    const f = await X_.caseFive(x, "bnd06");
    const succ = X_.rootSuccessorAddress(x, f.recA), live = (await X_.rootRec(x)).live.address;
    const from = x.node.reads().length;
    let spentAfterReads = null;
    x.node.afterRead(isReadOf(succ), succ === live ? 4 : 2, () => { spentAfterReads = readsSince(x, succ, from); x.node.spendOutpoint(f.rootOut); });
    const r = await writesNothing(x, "A's root successor spent between the bracket and the completion", () => X_.verify(x));
    assert.ok(spentAfterReads !== null, "the spend landed after the bracket re-read");
    assert.ok(readsSince(x, succ, from) > spentAfterReads, "the completion read A's root successor address after the spend");
    X_.assertUnknown(r, "BND-06");
    X_.assertAttributionOutcome(r, "COMPLETION_REFUSED", { requestId: f.A, label: "BND-06" });
    assert.equal((await x.rootReq(f.A)).state, "REFUSED", "A is unchanged (no recordCompletionFailure before the marker)");
    assert.equal(await X_.receiptOf(x, f.X), null, "no receipt for A's txid");
    const r2 = await writesNothing(x, "the next Verify", () => X_.verify(x));
    X_.assertUnknown(r2, "BND-06 next Verify");
    X_.assertAttributionOutcome(r2, "NO_CANDIDATE", { label: "BND-06 next Verify" });
  });

  /* =============================== AFT: after attribution; crash replay =============================== */
  leg("AFT-01 FULL, then T1's new output is spent outside PolicyVault: the next Verify answers the root CONSISTENT and T1 UNKNOWN; a T1 build is refused 409 RECORDED_OUTPUT_SPENT naming T1's recorded outpoint, writing nothing; root FREEZE, UNFREEZE and T2 FREEZE (K) + emergency pause reach CHAIN_VERIFIED [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "aft01");
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    const t1 = await x.vault(ctx.T1);
    KK.outOfAppAgentSpend(x, { template: t1.template, state: f.recA.build.successorState, outpoint: f.vaultOut, covenantId: t1.live.covenantId, registry: f.recA.newRegistry, delegate: ctx.w.n1, recipient: ctx.w.recipient.xonly });
    const r = await X_.verify(x);
    assert.equal(r.root.status, "CONSISTENT", `the root stays usable (${r.root.status})`);
    assert.equal(X_.vaultResult(r, ctx.T1)?.status, "UNKNOWN", "T1 answers UNKNOWN");
    const res = await refused(x, "a T1 build after its recorded output was spent", () => X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "aft01-pz1"), 409, "RECORDED_OUTPUT_SPENT");
    assert.ok(lower(res.message).includes(`${f.X}:${f.vaultOut.index}`), `names T1's recorded outpoint (${res.message})`);
    await X_.ops.rootFreeze(x, "aft01-fz");
    await X_.ops.unfreeze(x, "aft01-uf");
    await X_.ops.emergencyPause(x, ctx.T2, "aft01-ep2");
  });

  /* WRITER DECISION 'PARTIAL upgrade' (RC45 C4-03a; owner criteria 3 and 4): it supersedes contract D3 (r2)'s "PARTIAL
   * never upgrades" for a LATER Verify. After a PARTIAL attribution, a later Verify that FRESHLY observes A's T1 successor
   * output exact and unspent at depth >= 1,000 upgrades: T1 is advanced to A's successor with A.newRegistry, A's marker
   * records mode FULL with the upgrade, T1 is no longer UNRESOLVED, and the answer never claims more than the evidence.
   * While that output is absent, contradictory or below depth, T1 stays UNRESOLVED and nothing is written. The Verify
   * that completes a PARTIAL replay still never reads T1 (addendum a item 2, AFT-02b); a later Verify may upgrade. The
   * AFT-02 leg below (C4-01's "the reappeared output is ignored") is rewritten to this decision. */
  leg("AFT-02 (PARTIAL upgrade, reorganization) PARTIAL (a delegate of A paid from T1's new output outside PolicyVault), then a reorganization reverses that payment — A's T1 successor output is back, exact and unspent at depth exactly 1,000 (A's accepting DAA), the payment's outputs are gone: the next Verify freshly reads it and upgrades — T1 advanced to A's successor with A's registry (one T1 generation), A's marker FULL (treasury ADVANCED) recording the upgrade, T1 no longer UNRESOLVED, the root answered CONSISTENT and nothing claimed beyond that evidence, the root record and T2 untouched by it; the Verify after it answers T1 CONSISTENT writing nothing, and T1 FREEZE (K) + emergency pause and UNFREEZE (M) reach CHAIN_VERIFIED [RED on d79f710]", async (x) => {
    const f = await partialCase(x, "aft02");
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL" });
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const t1succ = X_.vaultSuccessorAddress(x, f.recA), from = x.node.reads().length;
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "AFT-02");
    assert.ok(readsSince(x, t1succ, from) >= 1, "the upgrade freshly read A's T1 successor in that Verify");
    assert.equal(await x.recordJson("ORG_ROOT", ctx.rootId), before.rootJson, "the root record is untouched by the upgrade");
    assert.equal(await x.recordJson("VAULT", ctx.T2), before.t2Json, "T2 is untouched by the upgrade");
    const r2 = await writesNothing(x, "the Verify after the upgrade", () => X_.verify(x));
    assert.equal(r2.root.status, "CONSISTENT", `the root stays CONSISTENT (${r2.root.status})`);
    assert.equal(X_.vaultResult(r2, ctx.T1)?.status, "CONSISTENT", "T1 reads back CONSISTENT at A's successor");
    await X_.ops.emergencyPause(x, ctx.T1, "aft02-ep1");
    await X_.ops.unfreeze(x, "aft02-uf1");
  });

  leg("UPG-01 (PARTIAL upgrade, transient ABSENT) the first Verify's node answers transiently omit A's T1 successor output (exact and unspent on chain throughout), so the attribution completes PARTIAL with T1 UNRESOLVED; the next Verify freshly observes it exact and unspent at depth 1,000 and upgrades (T1 advanced with A's registry, the marker FULL recording the upgrade, T1 no longer UNRESOLVED, the root answered CONSISTENT, nothing claimed beyond that evidence); the Verify after it writes nothing [RED on d79f710]", async (x) => {
    const f = await X_.caseFive(x, "upg01");
    const r1 = await X_.verify(x, { rpc: omittingRpc(x.node.rpc, f.vaultOut) });
    X_.assertAttributedAdvanced(r1, f, { mode: "PARTIAL" });
    const before = await upgradeBefore(x, f);
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "UPG-01");
    const r2 = await writesNothing(x, "the Verify after the upgrade", () => X_.verify(x));
    assert.equal(X_.vaultResult(r2, ctx.T1)?.status, "CONSISTENT");
  });

  leg("UPG-02 (PARTIAL upgrade, the root moved on) after the PARTIAL attribution the root moves on through a hosted T2 AUTHORIZE + pause (A's root successor is spent), then a reorganization reverses the outside payment from T1: the next Verify still upgrades T1 from its own fresh evidence (A's T1 successor exact and unspent at depth 1,000), the root record and T2 untouched by it [RED on d79f710]", async (x) => {
    const f = await partialCase(x, "upg02");
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL" });
    await X_.ops.pause(x, ctx.T2, "upg02-pz2");
    assert.equal(x.node.entryAt(f.rootOut), null, "precondition: A's root successor is spent by the hosted action");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "UPG-02");
    assert.equal(await x.recordJson("ORG_ROOT", ctx.rootId), before.rootJson, "the root record is untouched by the upgrade");
    assert.equal(await x.recordJson("VAULT", ctx.T2), before.t2Json, "T2 is untouched by the upgrade");
  });

  leg("UPG-03 (no upgrade while absent or contradictory) after the PARTIAL attribution, each later Verify writes nothing and T1 stays UNRESOLVED (record and PARTIAL marker unchanged, no FULL or advanced claim) while A's T1 successor output is: still spent; back with another value / covenant id / script / no reported script; back twice under A's txid at its address; back exact but re-accepted below depth (999); back exact while T1's recorded predecessor (A's T1 input) is reported unspent again [PIN: holds on d79f710]", async (x) => {
    const f = await partialCase(x, "upg03");
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL" });
    const before = await upgradeBefore(x, f);
    const E = f.t1Entry, put = (patch) => x.node.putEntry(E.address, { ...E.entry, ...patch });
    const other = { transactionId: f.X, index: 97 };
    const variants = [
      ["still spent", () => {}],
      ["back with another value", () => put({ amount: BigInt(E.entry.amount) + 1n })],
      ["back with another covenant id", () => put({ covenantId: K.hex("rc45-c403a-upg03-other-covenant") })],
      ["back with another script", () => put({ scriptPublicKey: { version: 0, script: `20${"11".repeat(32)}ac` } })],
      ["back with no reported script", () => put({ scriptPublicKey: { version: 0, script: null } })],
      ["back twice under A's txid at its address", () => { put({}); put({ outpoint: other }); }],
      ["back exact but re-accepted below depth (999)", () => put({ daaStamp: (x.node.state.daa - (DEPTH - 1n)).toString() })],
      ["back exact while T1's recorded predecessor is reported unspent again", () => { put({}); x.node.putEntry(f.t1Pred.address, f.t1Pred.entry); }]
    ];
    for (const [label, edit] of variants) {
      edit();
      const r = await writesNothing(x, label, () => X_.verify(x));
      await assertStillUnresolved(x, f, r, before, label, { t1Result: !label.includes("predecessor") });
      for (const op of [f.vaultOut, other, f.t1Pred.entry.outpoint]) x.node.spendOutpoint(op);
    }
  });

  leg("UPG-04 (PARTIAL upgrade after a PARTIAL replay) a crash right after the PARTIAL marker save, then a reorganization reverses the outside payment: the replay Verify still never reads T1 and completes the root PARTIAL with T1 byte-identical (the Verify that completes PARTIAL never upgrades); the Verify after it freshly observes A's T1 successor exact and unspent at depth 1,000 and upgrades [RED on d79f710]", async (x) => {
    const f = await partialCase(x, "upg04");
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === f.A && op.value?.outOfBandAttribution?.mode === "PARTIAL");
    await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, "the Verify reached the PARTIAL marker save (the crash is injected right after it)");
    reorgReversesPayment(x, f);
    const t1Json = await x.recordJson("VAULT", ctx.T1), t1succ = X_.vaultSuccessorAddress(x, f.recA), from = x.node.reads().length;
    X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL" });
    assert.equal(readsSince(x, t1succ, from), 0, "the PARTIAL replay never reads T1's successor");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is byte-identical after the replay");
    const before = await upgradeBefore(x, f);
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "UPG-04");
  });

  test(`RC45 L2-01 ${backend}: UPG-05 (PARTIAL upgrade, crash) a crash after each durable write of the upgrade (all later writes fail): the next Verify completes it exactly once — T1 advanced to A's successor with A's registry in exactly one T1 generation, the marker FULL recording the upgrade, T1 no longer UNRESOLVED, nothing holding the root, its answer CONSISTENT or the attribution replay answer naming A; the first crash point at which no later write fails is the uninterrupted upgrade (whatever the number of writes) [RED on d79f710]`, { skip }, async () => {
    const covered = [];
    for (let k = 1; k <= 12; k++) {
      const x = await X_.fresh(backend);
      try {
        const f = await partialCase(x, `upg05-${k}`);
        X_.assertAttributedAdvanced(await X_.verify(x), f, { mode: "PARTIAL" });
        const before = await upgradeBefore(x, f);
        reorgReversesPayment(x, f);
        const faults = X_.storeFaults(x);
        faults.crashAfter((op, log) => log.length === k);
        const first = await X_.verifySettled(x);
        const interrupted = faults.interrupted(), writes = faults.log().length;
        faults.restore();
        if (!interrupted) {
          assert.ok(writes > 0, `the upgrade Verify makes at least one durable write; it made ${writes} and answered ${JSON.stringify(first.result?.root ?? first.thrown?.message)}`);
          assert.ok(first.result, `uninterrupted (k = ${k}, ${writes} writes): the Verify returns (${first.thrown?.message})`);
          await assertUpgraded(x, f, first.result, before, `uninterrupted (k = ${k}, ${writes} writes)`);
          covered.push({ k, uninterrupted: true, writes });
          break;
        }
        const r = await X_.verify(x);
        await assertUpgraded(x, f, r, before, `the Verify after a crash after write ${k}`, { replay: true });
        assert.equal((await X_.rootRec(x)).pendingRequestId, null, `crash after write ${k}: nothing holds the root`);
        const r2 = await writesNothing(x, `the Verify after the completed upgrade (crash after write ${k})`, () => X_.verify(x));
        assert.equal(X_.vaultResult(r2, ctx.T1)?.status, "CONSISTENT", `crash after write ${k}: T1 reads back CONSISTENT`);
        covered.push({ k });
      } finally { await X_.release(x); }
    }
    assert.ok(covered.some((c) => c.uninterrupted), "every crash point of the upgrade was covered");
  });

  /* ---------- RC45 C4-03c: C4-03b item check F-01 — crash safety once the root moved on ---------- */
  test(`RC45 L2-01 ${backend}: UPG-06 (upgrade crash, the root moved on, the restored output spent again) after the PARTIAL attribution the root moves on (hosted T2 AUTHORIZE + pause), a reorganization reverses the outside payment and the upgrade Verify crashes after each of its durable writes (all later writes fail); then the reversed payment is accepted again (A's restored T1 successor is spent once more): every later Verify answers and never throws, nothing holds the root and a root FREEZE builds, no Verify writes T1 at the spent output, and A's marker never stays FULL over T1's spent record — with T1 still at its predecessor the marker is downgraded to PARTIAL with T1 UNRESOLVED (addendum a item 1(b)); the Verify after that writes nothing; the first crash point at which no later write fails is the uninterrupted upgrade, after which the spend leaves every Verify answering, T1 never re-written and not answered as current [RED on b387ff0]`, { skip }, async () => {
    const covered = [];
    for (let k = 1; k <= 12; k++) {
      const x = await X_.fresh(backend);
      try {
        const f = await attributedPartial(x, `upg06-${k}`, { rootMovesOn: true });
        const before = await upgradeBefore(x, f);
        reversePaymentKeeping(x, f);
        const faults = X_.storeFaults(x);
        faults.crashAfter((op, log) => log.length === k);
        const first = await X_.verifySettled(x);
        const interrupted = faults.interrupted(), writes = faults.log().length;
        faults.restore();
        const label = interrupted ? `crash after write ${k}` : `uninterrupted (k = ${k}, ${writes} writes)`;
        if (!interrupted) {
          assert.ok(writes > 0, `the upgrade Verify makes at least one durable write; it made ${writes} and answered ${JSON.stringify(first.result?.root ?? first.thrown?.message)}`);
          assert.ok(first.result, `${label}: the Verify returns (${first.thrown?.message})`);
          await assertUpgraded(x, f, first.result, before, label);
        }
        const t1AtCrash = await x.vault(ctx.T1), t1JsonAtCrash = await x.recordJson("VAULT", ctx.T1);
        const t1Written = sameOp(t1AtCrash.live.outpoint, f.vaultOut);
        if (!t1Written) assert.equal(t1JsonAtCrash, before.t1Json, `${label}: T1 not yet written stands at its predecessor, byte-identical`);
        paymentAcceptedAgain(x, f);
        for (let i = 1; i <= 2; i++) {
          const s = await X_.verifySettled(x);
          assert.ok(s.result, `${label}, then T1's restored output spent again: Verify ${i} answers, never throws (${s.thrown ? `${s.thrown.code} ${s.thrown.message}` : ""})`);
          const r = s.result;
          assert.equal(r.root.treasuryUpgrades, undefined, `${label}: Verify ${i} reports no upgrade over a spent output (${JSON.stringify(r.root.treasuryUpgrades)})`);
          if (!t1Written) assert.notEqual(r.root.mode, "FULL", `${label}: Verify ${i} gives no FULL answer while T1's record is at its spent predecessor (${JSON.stringify(r.root)})`);
          const v = X_.vaultResult(r, ctx.T1);
          assert.ok(!v || !["CONSISTENT", "ADVANCED"].includes(v.status), `${label}: Verify ${i} does not answer T1 as current (${JSON.stringify(v)})`);
        }
        assert.equal(await x.recordJson("VAULT", ctx.T1), t1JsonAtCrash, `${label}: no Verify writes T1 after its output was spent again (no known-spent adoption)`);
        const a = await x.rootReq(f.A);
        assert.ok(wr7().boundAttributionMarker(a), `${label}: A's marker still binds (${JSON.stringify(a.outOfBandAttribution)})`);
        assert.equal(a.state, "CHAIN_VERIFIED", `${label}: A stays CHAIN_VERIFIED`);
        assert.equal(a.finalTransaction, undefined, `${label}: no final transaction is invented`);
        if (!t1Written) {
          assert.equal(a.outOfBandAttribution.mode, "PARTIAL", `${label}: with T1 at its predecessor and its expected output spent, A's marker is downgraded to PARTIAL (never FULL over a spent T1 record)`);
          assert.equal(a.outOfBandAttribution.treasury.state, "UNRESOLVED", `${label}: the marker records T1 UNRESOLVED`);
          assert.ok(await wr7().treasuryUnresolved(x.config, await x.vault(ctx.T1)), `${label}: T1 is UNRESOLVED (D7 names it)`);
        }
        assert.equal((await X_.rootRec(x)).pendingRequestId, null, `${label}: nothing holds the root`);
        const r3 = await writesNothing(x, `${label}: the Verify after`, () => X_.verify(x));
        assert.equal(r3.root.status, "CONSISTENT", `${label}: the root reads back CONSISTENT (${r3.root.status} ${r3.root.reason ?? ""})`);
        const fz = await X_.rootOnly(x, "freeze", `upg06-${k}-fz`);
        assert.equal(fz.status, 201, `${label}: a root FREEZE builds (${said(fz)})`);
        covered.push({ k, uninterrupted: !interrupted, t1Written, writes });
        if (!interrupted) break;
      } finally { await X_.release(x); }
    }
    assert.ok(covered.some((c) => c.uninterrupted), "every crash point of the upgrade was covered");
    assert.ok(covered.some((c) => !c.uninterrupted), "at least one crash point interrupts the upgrade");
  });

  leg("UPG-06b (upgrade crash, the root moved on, the restored output spent again; an ordinary race on the root) in UPG-06's state after a crash right after the upgrade's marker write, an ordinary hosted request B (T2 AUTHORIZE + unpause) is built, signed, finalized and submitted, and an accepted competing transaction spends T2's output after B's submit start (the node answers orphan: B holds the root's reservation and its claims): Verify answers (never throws), proves B SUPERSEDED and releases its claims and the reservation; A's marker ends PARTIAL with T1 UNRESOLVED and byte-identical; a root FREEZE builds — the root is never left held [RED on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg06b", { rootMovesOn: true });
    const before = await upgradeBefore(x, f);
    reversePaymentKeeping(x, f);
    const faults = X_.storeFaults(x);
    faults.crashAfter(upgradeMarkerSave(f));
    const first = await X_.verifySettled(x);
    const interrupted = faults.interrupted();
    faults.restore();
    assert.ok(interrupted, `the crash interrupted the upgrade right after its marker write (${JSON.stringify(first.result?.root ?? first.thrown?.message)})`);
    assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, "precondition: T1 is not written");
    paymentAcceptedAgain(x, f);
    const t2 = await x.vault(ctx.T2);
    const b = await X_.vaultOp(x, ctx.T2, "ownerUnpause", "authorize", "upg06b-b");
    assert.equal(b.status, 201, `B is built (${said(b)})`);
    const id = b.body.request.id;
    await X_.sign(x, id, [1, 2]);
    const fin = await x.rootFinalize(ctx.rootId, id);
    assert.equal(fin.status, 200, `B is finalized (${said(fin)})`);
    const q = await x.rootReq(id);
    KK.seedFee(x, q);
    const rpc = KK.outcomeRpc(x, { submitAnswer: "strict", frozen: q.build.frozen, conflict: { outpoint: t2.live.outpoint, payToXOnly: ctx.w.stranger.xonly } });
    const sub = await KK.NODE().with(rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "submit"], {}, x.cookie.o1));
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `B's submit is answered orphan (${said(sub)})`);
    assert.equal((await X_.rootRec(x)).pendingRequestId, id, "precondition: B holds the root's reservation");
    const answers = [];
    for (let i = 1; i <= 2 && (await X_.rootRec(x)).pendingRequestId !== null; i++) {
      const s = await X_.verifySettled(x, { rpc });
      answers.push(s.result ? `${s.result.root.status} ${s.result.root.reason ?? ""}` : `THROWN ${s.thrown.code} ${s.thrown.message}`);
      assert.ok(s.result, `Verify ${i} answers, never throws (${answers[answers.length - 1]})`);
    }
    assert.equal((await x.rootReq(id)).state, "SUPERSEDED", `B is proven SUPERSEDED (${JSON.stringify(answers)})`);
    assert.equal(await X_.transitionClaim(x, q.manifest.root.outpoint), null, "B's root claim is released");
    assert.equal(await X_.submissionClaim(x, q.txId), null, "B's submission claim is released");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing holds the root");
    const a = await x.rootReq(f.A);
    assert.ok(wr7().boundAttributionMarker(a), "A's marker binds");
    assert.equal(a.outOfBandAttribution.mode, "PARTIAL", "A's marker is not left FULL over T1's spent record");
    assert.equal(a.outOfBandAttribution.treasury.state, "UNRESOLVED");
    assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, "T1 is never written");
    assert.ok(await wr7().treasuryUnresolved(x.config, await x.vault(ctx.T1)), "T1 is UNRESOLVED");
    const fz = await X_.rootOnly(x, "freeze", "upg06b-fz");
    assert.equal(fz.status, 201, `a root FREEZE builds (${said(fz)})`);
  });

  leg("UPG-06c (completed upgrade, the root moved on, the restored output spent again) after the PARTIAL attribution the root moves on, the reorganization reverses the outside payment and a Verify upgrades T1 (uninterrupted); then the reversed payment is accepted again: the next Verify answers the root CONSISTENT and T1 not as current, never re-writes T1; a T1 build is refused 409 RECORDED_OUTPUT_SPENT naming T1's recorded outpoint (A's treasury successor), writing nothing (the C4-04 guard, as AFT-01); root FREEZE, UNFREEZE and T2 AUTHORIZE + unpause reach CHAIN_VERIFIED [RED on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg06c", { rootMovesOn: true });
    const before = await upgradeBefore(x, f);
    reversePaymentKeeping(x, f);
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-06c upgrade");
    paymentAcceptedAgain(x, f);
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    const r = await X_.verify(x);
    assert.equal(r.root.status, "CONSISTENT", `the root stays usable (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported");
    assert.ok(!["CONSISTENT", "ADVANCED"].includes(X_.vaultResult(r, ctx.T1)?.status), `T1 is not answered as current (${JSON.stringify(X_.vaultResult(r, ctx.T1))})`);
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is never re-written");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing holds the root");
    const res = await refused(x, "a T1 build after its recorded output was spent again", () => X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "upg06c-pz1"), 409, "RECORDED_OUTPUT_SPENT");
    assert.ok(lower(res.message).includes(`${f.X}:${f.vaultOut.index}`), `names T1's recorded outpoint (${res.message})`);
    await X_.ops.rootFreeze(x, "upg06c-fz");
    await X_.ops.unfreeze(x, "upg06c-uf");
    await X_.ops.unpause(x, ctx.T2, "upg06c-up2");
  });

  /* ---------- RC45 C4-03c: C4-03b item check F-02 — the bracket, the depth rule alone and a failed treasury write ---------- */
  leg("UPG-07 (the upgrade's bracket: T1's second read) A's restored T1 successor is spent right after the upgrade's FIRST read of it (that read answered EXACT; the root is still at A's successor and every other rule holds): the upgrade's second read sees it gone — nothing written, no upgrade reported, T1 stays UNRESOLVED with its record and PARTIAL marker unchanged [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg07");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const t1succ = X_.vaultSuccessorAddress(x, f.recA), from = x.node.reads().length;
    x.node.afterRead(isReadOf(t1succ), 1, () => x.node.spendOutpoint(f.vaultOut));
    const r = await writesNothing(x, "T1 spent between the upgrade's two reads", () => X_.verify(x));
    assert.ok(readsSince(x, t1succ, from) >= 2, `the Verify read A's T1 successor a second time (the bracket); it read it ${readsSince(x, t1succ, from)} time(s)`);
    assert.equal(r.root.treasuryUpgrades, undefined, `no upgrade is reported (${JSON.stringify(r.root.treasuryUpgrades)})`);
    await assertStillUnresolved(x, f, r, before, "UPG-07");
  });

  leg("UPG-08a (the depth rule alone, the root moved on) with the root moved on there is no root re-read and so no root/T1 accepting-DAA comparison: A's restored T1 successor, exact and unspent but re-accepted at depth 999, upgrades nothing (nothing written, T1 UNRESOLVED); one DAA later (depth exactly 1,000) the Verify upgrades [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg08a", { rootMovesOn: true });
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    x.node.mutateEntry(f.vaultOut, { daaStamp: (x.node.state.daa - (DEPTH - 1n)).toString() });
    const r = await writesNothing(x, "depth 999, root moved on", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported below depth");
    await assertStillUnresolved(x, f, r, before, "UPG-08a depth 999");
    x.node.state.daa += 1n;
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-08a depth 1,000");
  });

  leg("UPG-08b (the depth rule alone, the root at A's successor) A's restored T1 successor and A's root successor both re-accepted at the same DAA, 999 below the virtual DAA (so the root/T1 accepting-DAA equality holds and only the depth rule refuses): nothing written, T1 UNRESOLVED; one DAA later (depth exactly 1,000) the Verify upgrades [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg08b");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const stamp = (x.node.state.daa - (DEPTH - 1n)).toString();
    x.node.mutateEntry(f.vaultOut, { daaStamp: stamp });
    x.node.mutateEntry(f.rootOut, { daaStamp: stamp });
    const r = await writesNothing(x, "depth 999, root and T1 at the same DAA", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported below depth");
    await assertStillUnresolved(x, f, r, before, "UPG-08b depth 999");
    x.node.state.daa += 1n;
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-08b depth 1,000");
  });

  leg("UPG-09 (a failed treasury write) the upgrade's T1 write fails after its marker write (the store fails from then on): that Verify never reports an upgrade — it throws, or answers without treasuryUpgrades and without T1 as current — and T1 is not written; the next Verify completes the upgrade exactly once and nothing holds the root [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg09");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const faults = X_.storeFaults(x);
    faults.crashAfter(upgradeMarkerSave(f));
    const first = await X_.verifySettled(x);
    const interrupted = faults.interrupted();
    faults.restore();
    assert.ok(interrupted, "the treasury write after the marker write failed");
    assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, "T1 is not written");
    if (first.result) {
      assert.equal(first.result.root.treasuryUpgrades, undefined, `a failed treasury write is never reported as an upgrade (${JSON.stringify(first.result.root)})`);
      const v = X_.vaultResult(first.result, ctx.T1);
      assert.ok(!v || !["CONSISTENT", "ADVANCED"].includes(v.status), `T1 is not answered as current (${JSON.stringify(v)})`);
    }
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-09 next Verify", { replay: true });
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing holds the root");
  });

  /* RC45 C4-08a (SAB04-F02, CF-U18): UPG-09's fault fails every mutation after the marker write, its event-line append
   * included; here exactly the T1 write fails, once */
  leg("UPG-09b (a single failed treasury write) exactly the upgrade's T1 write fails, once, right after its marker write, and every other write (the upgrade's event line included) succeeds: that Verify never reports an upgrade (it throws RECONCILIATION_REQUIRED, or answers without treasuryUpgrades, without mode FULL and without T1 as current), T1's record is not written, no event line records the upgrade, and a hosted T1 build is refused 409 RECORDED_OUTPUT_SPENT writing nothing; the next Verify completes the upgrade exactly once and the Verify after it writes nothing [PIN: holds on f267cca]", async (x) => {
    const f = await attributedPartial(x, "upg09b");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const lines0 = await auditLines(x);
    const fault = singleWriteFault(x, { after: upgradeMarkerSave(f), pred: (op) => op.category === C().VAULT && op.key === ctx.T1 });
    let first;
    try { first = await X_.verifySettled(x); } finally { fault.restore(); }
    assert.equal(fault.failures(), 1, "exactly one write failed: the upgrade's T1 write, after its marker write");
    assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, "T1's record is not written");
    if (first.thrown) {
      assert.equal(first.thrown.code, "RECONCILIATION_REQUIRED", `a throw is the upgrade's own refusal, never the store fault itself (${first.thrown.code}: ${first.thrown.message})`);
    } else {
      const r = first.result;
      assert.equal(r.root.treasuryUpgrades, undefined, `a failed treasury write is never reported as an upgrade (${JSON.stringify(r.root.treasuryUpgrades)})`);
      assert.notEqual(r.root.mode, "FULL", "the answer claims no mode FULL over the unwritten T1");
      if (r.root.treasury !== undefined) assert.notEqual(r.root.treasury.state, "ADVANCED", "a treasury in the answer is not ADVANCED");
      const v = X_.vaultResult(r, ctx.T1);
      assert.ok(!v || !["CONSISTENT", "ADVANCED"].includes(v.status), `T1 is not answered as current (${JSON.stringify(v)})`);
    }
    const added = addedLines(lines0, await auditLines(x));
    assert.deepEqual(added.filter(isUpgradeLine), [], `no event line records the upgrade while T1's record is unwritten (${JSON.stringify(added)})`);
    await refused(x, "a hosted T1 build while T1's record is unwritten", () => X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "upg09b-pz"), 409, "RECORDED_OUTPUT_SPENT");
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-09b next Verify", { replay: true });
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing holds the root");
    await writesNothing(x, "the Verify after the completed upgrade", () => X_.verify(x));
  });

  /* ---------- RC45 C4-03c: C4-03b item check F-03 — the remaining upgrade rules, each isolated ---------- */
  leg("UPG-10 (the claim-release gate) with A's restored T1 successor exact and unspent at depth, a Verify without claim release (allowClaimRelease false) never upgrades: no DAA read, no read of A's T1 successor, nothing written, T1 UNRESOLVED; a Verify with claim release then upgrades [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg10");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const t1succ = X_.vaultSuccessorAddress(x, f.recA), from = x.node.reads().length;
    const r = await writesNothing(x, "Verify without claim release", () => X_.verify(x, { allowClaimRelease: false }));
    assert.equal(x.node.reads().slice(from).filter((c) => c.method === "getBlockDagInfo").length, 0, "no DAA read");
    assert.equal(readsSince(x, t1succ, from), 0, "no read of A's T1 successor");
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported");
    await assertStillUnresolved(x, f, r, before, "UPG-10");
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-10 with claim release");
  });

  leg("UPG-11 (the no-discovery-replay gate) a crash right after the PARTIAL completion's root write (the root record at A's root successor, A not yet CHAIN_VERIFIED), then a reorganization reverses the outside payment: the Verify whose discovery replays A completes it PARTIAL and does not upgrade — no read of A's T1 successor, no upgrade reported, T1 byte-identical, the marker PARTIAL; the next Verify upgrades [PIN: holds on b387ff0]", async (x) => {
    const f = await partialCase(x, "upg11");
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT && op.value && op.value.live && sameOp(op.value.live.outpoint, f.rootOut));
    const first = await X_.verifySettled(x);
    const interrupted = faults.interrupted();
    faults.restore();
    assert.ok(interrupted, `the crash after the root write interrupted the completion (${JSON.stringify(first.result?.root ?? first.thrown?.message)})`);
    const a1 = await x.rootReq(f.A);
    assert.equal(a1.outOfBandAttribution?.mode, "PARTIAL", "precondition: A carries the PARTIAL marker");
    assert.notEqual(a1.state, "CHAIN_VERIFIED", "precondition: A is not yet CHAIN_VERIFIED");
    assert.ok(sameOp((await X_.rootRec(x)).live.outpoint, f.rootOut), "precondition: the root record follows A's root successor");
    reorgReversesPayment(x, f);
    const t1Json = await x.recordJson("VAULT", ctx.T1), t1succ = X_.vaultSuccessorAddress(x, f.recA), from = x.node.reads().length;
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL", replay: true, label: "the discovery replay Verify" });
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade in the Verify whose discovery replayed A");
    assert.equal(readsSince(x, t1succ, from), 0, "the replay Verify never reads A's T1 successor");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is byte-identical after the replay Verify");
    assert.equal((await x.rootReq(f.A)).outOfBandAttribution.mode, "PARTIAL", "the marker stays PARTIAL in the replay Verify");
    assert.equal((await x.rootReq(f.A)).state, "CHAIN_VERIFIED", "the replay completed A");
    const before = await upgradeBefore(x, f);
    const r2 = await X_.verify(x);
    await assertUpgraded(x, f, r2, before, "UPG-11 next Verify");
    assert.equal(r2.root.treasuryUpgrades?.length, 1, "the upgrade is reported once");
  });

  leg("UPG-12 (AMBIGUOUS) two bound PARTIAL markers name T1's recorded outpoint (a store clone of A with an older createdAt whose marker names the clone), A's restored T1 successor exact and unspent at depth: nothing written, no upgrade reported, T1 UNRESOLVED [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg12");
    const clone = structuredClone(await x.store.read(C().ORG_ROOT_REQUEST, f.A));
    clone.id = crypto.randomUUID();
    clone.createdAt = "2000-01-01T00:00:00.000Z";
    clone.outOfBandAttribution.requestId = clone.id;
    await x.store.write(C().ORG_ROOT_REQUEST, clone.id, clone);
    assert.ok(wr7().boundAttributionMarker(await x.rootReq(clone.id)), "precondition: the clone's marker binds");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const r = await writesNothing(x, "two markers name T1's recorded outpoint", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported");
    await assertStillUnresolved(x, f, r, before, "UPG-12");
  });

  leg("UPG-13 (the binding of A's recorded transaction) A's redeem scripts removed from its record (A still verifies complete; the attributed binding refuses it), A's restored T1 successor exact and unspent at depth: nothing written, no upgrade reported, T1 UNRESOLVED [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg13");
    const a = await x.store.read(C().ORG_ROOT_REQUEST, f.A);
    assert.ok(a.redeemScripts && Object.keys(a.redeemScripts).length > 0, "precondition: A carries redeem scripts");
    a.redeemScripts = {};
    await x.store.write(C().ORG_ROOT_REQUEST, f.A, a);
    assert.equal((await wr7().verifyRootActionCompletion(x.config, await x.rootReq(f.A))).complete, true, "precondition: A still verifies complete");
    assert.throws(() => wr7().assertRequestTransactionBinding(x.config, a), /damaged/i, "precondition: the attributed binding refuses A");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const r = await writesNothing(x, "A's binding fails", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported");
    await assertStillUnresolved(x, f, r, before, "UPG-13");
  });

  leg("UPG-14 (the root successor re-read) with the root record at A's root successor, that output is spent right after the upgrade's first read of A's T1 successor: the upgrade's re-read of the root successor sees it gone — nothing written, no upgrade reported, T1 UNRESOLVED [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg14");
    assert.ok(sameOp((await X_.rootRec(x)).live.outpoint, f.rootOut), "precondition: the root record follows A's root successor");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    x.node.afterRead(isReadOf(X_.vaultSuccessorAddress(x, f.recA)), 1, () => x.node.spendOutpoint(f.rootOut));
    const r = await writesNothing(x, "the root successor spent mid-upgrade", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported");
    await assertStillUnresolved(x, f, r, before, "UPG-14");
  });

  leg("UPG-15 (the root/T1 accepting-DAA equality) with the root at A's successor, A's restored T1 successor exact and unspent at depth 1,001 (its accepting DAA one below the root successor's): nothing written, no upgrade reported, T1 UNRESOLVED [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg15");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const stamp = BigInt(x.node.entryAt(f.vaultOut).entry.daaStamp);
    assert.equal(String(x.node.entryAt(f.rootOut).entry.daaStamp), String(stamp), "precondition: the root and T1 successors share A's accepting DAA");
    x.node.mutateEntry(f.vaultOut, { daaStamp: (stamp - 1n).toString() });
    const r = await writesNothing(x, "the root and T1 accepting DAA differ", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, "no upgrade is reported");
    await assertStillUnresolved(x, f, r, before, "UPG-15");
  });

  leg("UPG-16 (a non-canonical accepting DAA on T1's entry) with the root moved on, A's restored T1 successor exact and unspent but reported with a non-canonical accepting DAA (hex '0x2f', negative, fractional, null): nothing written, no upgrade reported, T1 UNRESOLVED; with the entry's canonical DAA restored the Verify upgrades [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg16", { rootMovesOn: true });
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    for (const raw of ["0x2f", "-5", "12.5", null]) {
      const label = `T1's accepting DAA ${JSON.stringify(raw)}`;
      const restore = x.node.mutateEntry(f.vaultOut, { daaStamp: raw });
      const r = await writesNothing(x, label, () => X_.verify(x));
      assert.equal(r.root.treasuryUpgrades, undefined, `${label}: no upgrade is reported`);
      await assertStillUnresolved(x, f, r, before, label);
      restore();
    }
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-16 canonical DAA");
  });

  leg("UPG-17 (a node read error inside the upgrade observation) the DAA read, the first and the second read of A's T1 successor, and the read of A's T1 input address each fail in turn: each Verify answers (never throws), the root answer is kept CONSISTENT, nothing written, no upgrade reported, T1 UNRESOLVED; then a working node upgrades [PIN: holds on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg17");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const t1succ = X_.vaultSuccessorAddress(x, f.recA), t1in = t1InputAddress(x, f.recA);
    const at = (address, nth) => X_.faultyRpc(x.node.rpc, { method: "getUtxosByAddresses", pred: ({ addresses }) => addresses.map(String).includes(address), nth });
    for (const [label, rpc] of [
      ["the DAA read", X_.faultyRpc(x.node.rpc, { method: "getBlockDagInfo", always: true })],
      ["the first read of A's T1 successor", at(t1succ, 1)],
      ["the second read of A's T1 successor", at(t1succ, 2)],
      ["the read of A's T1 input address", at(t1in, 1)]
    ]) {
      const s = await writesNothing(x, label, () => X_.verifySettled(x, { rpc }));
      assert.ok(s.result, `${label}: the Verify answers, never throws (${s.thrown ? `${s.thrown.code} ${s.thrown.message}` : ""})`);
      assert.equal(s.result.root.status, "CONSISTENT", `${label}: the root answer is kept (${s.result.root.status} ${s.result.root.reason ?? ""})`);
      assert.equal(s.result.root.treasuryUpgrades, undefined, `${label}: no upgrade is reported`);
      await assertStillUnresolved(x, f, s.result, before, label);
    }
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-17 working node");
  });

  /* ---------- RC45 C4-03c: C4-03b item check F-05 and F-07 ---------- */
  leg("UPG-18 (the replay answer after the upgrade's crash window, the root moved on) after the PARTIAL attribution the root moves on, the reorganization reverses the outside payment and the upgrade Verify crashes right after its marker write; the next Verify completes T1 exactly once (A's successor, A's registry, one generation, the marker FULL, nothing holding the root, the root record's position and generation unchanged) and its answer never claims that the root follows A's successor: the root record stands beyond it and did not move in that Verify [RED on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg18", { rootMovesOn: true });
    const before = await upgradeBefore(x, f);
    const root0 = await X_.rootRec(x);
    reorgReversesPayment(x, f);
    const faults = X_.storeFaults(x);
    faults.crashAfter(upgradeMarkerSave(f));
    const first = await X_.verifySettled(x);
    const interrupted = faults.interrupted();
    faults.restore();
    assert.ok(interrupted, `the crash interrupted the upgrade right after its marker write (${JSON.stringify(first.result?.root ?? first.thrown?.message)})`);
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "UPG-18", { replay: true });
    const root1 = await X_.rootRec(x);
    assert.ok(sameOp(root1.live.outpoint, root0.live.outpoint), "the root record's position did not move");
    assert.equal(Number(root1.generation ?? 0), Number(root0.generation ?? 0), "the root record's generation did not move");
    assert.equal(root1.pendingRequestId, null, "nothing holds the root");
    assert.doesNotMatch(String(r.root.reason ?? ""), ROOT_FOLLOWS, `the answer does not claim that the root follows A's successor (status ${r.root.status}; reason: ${r.root.reason})`);
  });

  leg("UPG-19 (the upgrade's event line) the upgrade Verify appends exactly one event line, naming treasury T1 and A's transaction (actor system), with no recovered / restored / repaired / fixed / resolved wording and without a second CHAIN_VERIFIED line for A's transaction; the Verify after it appends none [RED on b387ff0]", async (x) => {
    const f = await attributedPartial(x, "upg19");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    const lines0 = await auditLines(x);
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "UPG-19");
    const added = addedLines(lines0, await auditLines(x));
    assert.equal(added.length, 1, `the upgrade appends exactly one event line (it appended ${added.length}: ${JSON.stringify(added)})`);
    const line = added[0], s = JSON.stringify(line);
    assert.ok(s.includes(ctx.T1), `the line names treasury T1 (${s})`);
    assert.ok(lower(s).includes(f.X), `the line names A's transaction (${s})`);
    assert.equal(line.actor, "system", `the line's actor is the system (${s})`);
    assert.doesNotMatch(s, OVERCLAIM, "the line never says recovered / restored / repaired / fixed / resolved");
    await X_.assertCompletedOnce(x, f, "A", { via: ["attribution"] });
    await writesNothing(x, "the Verify after the upgrade", () => X_.verify(x));
  });

  /* ---------- RC45 C4-04a (tests only): the C4-03d item check F-01 (the PARTIAL-marker half of the replay exemption),
   * F-02 (the upgrade's event line: after T1's write; a failed append never reported) and F-03 (the at-successor replay
   * wording; the exemption limited to a treasury record at its predecessor), the C4-03b item check F-08 (the upgrade's
   * completion precondition when discovery cannot reach A) and contract D2.2 (the candidate cap). Their labels name the
   * C4-04 head: [PIN: holds on 691ebcf] passes there and must keep passing. ---------- */
  test(`RC45 L2-01 ${backend}: UPG-20 (downgrade crash, the root moved on) after the PARTIAL attribution the root moves on (hosted T2 AUTHORIZE + pause), a reorganization reverses the outside payment, the upgrade Verify crashes right after its marker write (A's marker FULL while T1's record is at its predecessor), then the reversed payment is accepted again; the Verify that downgrades A's marker to PARTIAL crashes after each of its durable writes (all later writes fail): every later Verify answers and never throws, reports no upgrade, gives no FULL answer and never says the root follows A's successor; T1 is never written; A ends CHAIN_VERIFIED with its bound marker PARTIAL and T1 UNRESOLVED; nothing holds the root, the Verify after writes nothing and a root FREEZE builds; a crash after the downgrade save that leaves A's durable completion unfinished with its PARTIAL marker (replayed with the root beyond A's successor) is covered, and the first crash point at which no later write fails is the uninterrupted downgrade [PIN: holds on 691ebcf]`, { skip }, async () => {
    const covered = [];
    for (let k = 1; k <= 12; k++) {
      const x = await X_.fresh(backend);
      try {
        const f = await attributedPartial(x, `upg20-${k}`, { rootMovesOn: true });
        const before = await upgradeBefore(x, f);
        reversePaymentKeeping(x, f);
        const f1 = X_.storeFaults(x);
        f1.crashAfter(upgradeMarkerSave(f));
        const s0 = await X_.verifySettled(x);
        const upgradeInterrupted = f1.interrupted();
        f1.restore();
        assert.ok(upgradeInterrupted, `the upgrade was interrupted right after its marker write (${JSON.stringify(s0.result?.root ?? s0.thrown?.message)})`);
        assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, "precondition: T1 is not written");
        assert.equal((await x.rootReq(f.A)).outOfBandAttribution.mode, "FULL", "precondition: A's marker is FULL while T1's record is at its predecessor");
        paymentAcceptedAgain(x, f);
        const f2 = X_.storeFaults(x);
        f2.crashAfter((op, log) => log.length === k);
        const s1 = await X_.verifySettled(x);
        const interrupted = f2.interrupted(), writes = f2.log().length;
        f2.restore();
        const label = interrupted ? `downgrade Verify crash after write ${k}` : `downgrade Verify uninterrupted (k = ${k}, ${writes} writes)`;
        if (!interrupted) {
          assert.ok(writes > 0, `the downgrade Verify makes at least one durable write; it made ${writes} and answered ${JSON.stringify(s1.result?.root ?? s1.thrown?.message)}`);
          assert.ok(s1.result, `${label}: the Verify returns (${s1.thrown ? `${s1.thrown.code} ${s1.thrown.message}` : ""})`);
        }
        const a1 = await x.rootReq(f.A);
        const partialPending = interrupted && a1.outOfBandAttribution?.mode === "PARTIAL" && !(await wr7().verifyRootActionCompletion(x.config, a1)).complete;
        const held = (await X_.rootRec(x)).pendingRequestId === f.A;
        for (let i = 1; i <= 2; i++) {
          const s = await X_.verifySettled(x);
          assert.ok(s.result, `${label}: Verify ${i} answers, never throws (${s.thrown ? `${s.thrown.code} ${s.thrown.message}` : ""})`);
          assert.equal(s.result.root.treasuryUpgrades, undefined, `${label}: Verify ${i} reports no upgrade (${JSON.stringify(s.result.root.treasuryUpgrades)})`);
          assert.notEqual(s.result.root.mode, "FULL", `${label}: Verify ${i} gives no FULL answer (${JSON.stringify(s.result.root)})`);
          assert.doesNotMatch(String(s.result.root.reason ?? ""), ROOT_FOLLOWS, `${label}: Verify ${i} never says the root follows A's successor (${s.result.root.reason})`);
        }
        assert.equal(await x.recordJson("VAULT", ctx.T1), before.t1Json, `${label}: T1 is never written`);
        const a = await x.rootReq(f.A);
        assert.ok(wr7().boundAttributionMarker(a), `${label}: A's marker still binds (${JSON.stringify(a.outOfBandAttribution)})`);
        assert.equal(a.state, "CHAIN_VERIFIED", `${label}: A ends CHAIN_VERIFIED`);
        assert.equal(a.outOfBandAttribution.mode, "PARTIAL", `${label}: A's marker ends PARTIAL (never FULL over T1's spent record)`);
        assert.equal(a.outOfBandAttribution.treasury.state, "UNRESOLVED", `${label}: the marker records T1 UNRESOLVED`);
        assert.ok(await wr7().treasuryUnresolved(x.config, await x.vault(ctx.T1)), `${label}: T1 is UNRESOLVED (D7 names it)`);
        assert.equal((await X_.rootRec(x)).pendingRequestId, null, `${label}: nothing holds the root`);
        await writesNothing(x, `${label}: the Verify after`, () => X_.verify(x));
        const fz = await X_.rootOnly(x, "freeze", `upg20-${k}-fz`);
        assert.equal(fz.status, 201, `${label}: a root FREEZE builds (${said(fz)})`);
        covered.push({ k, uninterrupted: !interrupted, partialPending, held, writes });
        if (!interrupted) break;
      } finally { await X_.release(x); }
    }
    assert.ok(covered.some((c) => c.uninterrupted), `the uninterrupted downgrade Verify was reached (${JSON.stringify(covered)})`);
    assert.ok(covered.some((c) => c.partialPending), `a crash after the downgrade save that leaves A's durable completion unfinished with its PARTIAL marker (to be replayed with the root beyond A's successor) was covered (${JSON.stringify(covered)})`);
  });

  test(`RC45 L2-01 ${backend}: UPG-21 (the upgrade's write order) the upgrade Verify crashes after each of its durable writes (all later writes fail): whenever an event line naming T1 has been appended, T1's record already follows A's successor (the line never precedes the record it states), and an upgrade is reported only with its one line; a crash before T1's write is covered, and the first crash point at which no later write fails is the uninterrupted upgrade, with T1 following A's successor and exactly one line [PIN: holds on 691ebcf]`, { skip }, async () => {
    const covered = [];
    for (let k = 1; k <= 12; k++) {
      const x = await X_.fresh(backend);
      try {
        const f = await attributedPartial(x, `upg21-${k}`);
        reorgReversesPayment(x, f);
        const lines0 = await auditLines(x);
        const faults = X_.storeFaults(x);
        faults.crashAfter((op, log) => log.length === k);
        const s = await X_.verifySettled(x);
        const interrupted = faults.interrupted(), writes = faults.log().length;
        faults.restore();
        const label = interrupted ? `crash after write ${k}` : `uninterrupted (k = ${k}, ${writes} writes)`;
        const t1Lines = addedLines(lines0, await auditLines(x)).filter((e) => JSON.stringify(e).includes(ctx.T1));
        const t1Follows = sameOp((await x.vault(ctx.T1)).live.outpoint, f.vaultOut);
        if (t1Lines.length > 0) assert.ok(t1Follows, `${label}: an event line naming T1 exists only once T1's record follows A's successor (lines ${JSON.stringify(t1Lines)})`);
        if (s.result && s.result.root.treasuryUpgrades !== undefined) assert.equal(t1Lines.length, 1, `${label}: an upgrade is reported only with its one event line (${JSON.stringify(s.result.root.treasuryUpgrades)})`);
        if (!interrupted) {
          assert.ok(s.result, `${label}: the Verify returns (${s.thrown ? `${s.thrown.code} ${s.thrown.message}` : ""})`);
          assert.ok(t1Follows, `${label}: T1's record follows A's successor`);
          assert.equal(t1Lines.length, 1, `${label}: exactly one event line names T1 (${JSON.stringify(t1Lines)})`);
        }
        covered.push({ k, uninterrupted: !interrupted, lines: t1Lines.length, t1Follows, writes });
        if (!interrupted) break;
      } finally { await X_.release(x); }
    }
    assert.ok(covered.some((c) => c.uninterrupted), `the uninterrupted upgrade was reached (${JSON.stringify(covered)})`);
    assert.ok(covered.some((c) => !c.uninterrupted && !c.t1Follows), `a crash before T1's write was covered (${JSON.stringify(covered)})`);
  });

  leg("UPG-22 (a failed event line) the append of the upgrade's event line fails after A's marker and T1's record were written (the store fails from then on): that Verify never reports an upgrade — it throws RECONCILIATION_REQUIRED naming T1, or answers without treasuryUpgrades; T1's record follows A's successor and A's marker is FULL (the records above the line are complete); the next Verify answers the root CONSISTENT, reports no upgrade, leaves T1's record and A's record unchanged, and nothing holds the root [PIN: holds on 691ebcf]", async (x) => {
    const f = await attributedPartial(x, "upg22");
    reorgReversesPayment(x, f);
    const faults = X_.storeFaults(x);
    faults.crashAt((op) => op.kind === "appendAudit" && JSON.stringify(op.value ?? null).includes(ctx.T1));
    const s = await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    const said1 = s.result ? JSON.stringify(s.result.root) : `THROWN ${s.thrown.code} ${s.thrown.message}`;
    assert.ok(crashed, `the append of an event line naming T1 was attempted and failed (${said1})`);
    if (s.result) {
      assert.equal(s.result.root.treasuryUpgrades, undefined, `no upgrade is reported when its event line failed (${said1})`);
    } else {
      assert.equal(s.thrown.code, "RECONCILIATION_REQUIRED", `the failed line is thrown RECONCILIATION_REQUIRED (${said1})`);
      assert.ok(String(s.thrown.message).includes(ctx.T1), `the thrown message names T1 (${said1})`);
    }
    assert.ok(sameOp((await x.vault(ctx.T1)).live.outpoint, f.vaultOut), "T1's record follows A's successor (written before the line)");
    assert.equal((await x.rootReq(f.A)).outOfBandAttribution.mode, "FULL", "A's marker records the upgrade (written before the line)");
    const t1Json = await x.recordJson("VAULT", ctx.T1), aJson = JSON.stringify(await x.rootReq(f.A));
    const r2 = await X_.verify(x);
    assert.equal(r2.root.status, "CONSISTENT", `the next Verify answers the root CONSISTENT (${r2.root.status} ${r2.root.reason ?? ""})`);
    assert.equal(r2.root.treasuryUpgrades, undefined, "the next Verify reports no upgrade");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "the next Verify leaves T1's record unchanged");
    assert.equal(JSON.stringify(await x.rootReq(f.A)), aJson, "the next Verify leaves A's record unchanged");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing holds the root");
  });

  leg("UPG-23 (the replay answer with the root at A's successor) the upgrade Verify crashes right after its marker write while the root record stands at A's root successor; the next Verify completes T1 exactly once and answers through the attribution replay — ADVANCED via attribution naming A — whose reason says that the root and treasury T1 follow A's successors and never that the root record stands beyond them [PIN: holds on 691ebcf]", async (x) => {
    const f = await attributedPartial(x, "upg23");
    const before = await upgradeBefore(x, f);
    reorgReversesPayment(x, f);
    assert.ok(sameOp((await X_.rootRec(x)).live.outpoint, f.rootOut), "precondition: the root record follows A's root successor");
    const faults = X_.storeFaults(x);
    faults.crashAfter(upgradeMarkerSave(f));
    const first = await X_.verifySettled(x);
    const interrupted = faults.interrupted();
    faults.restore();
    assert.ok(interrupted, `the crash interrupted the upgrade right after its marker write (${JSON.stringify(first.result?.root ?? first.thrown?.message)})`);
    const r = await X_.verify(x);
    await assertUpgraded(x, f, r, before, "UPG-23", { replay: true });
    assert.equal(r.root.status, "ADVANCED", `the attribution replay answer (${r.root.status} ${r.root.reason ?? ""})`);
    const reason = String(r.root.reason ?? "");
    assert.match(reason, ROOT_FOLLOWS, `with the root record at A's root successor the reason says the root follows it (${reason})`);
    assert.ok(reason.includes(ctx.T1), `the reason names treasury T1 (${reason})`);
    assert.doesNotMatch(reason, /\bbeyond\b/i, `no 'beyond' wording while the root record stands at A's root successor (${reason})`);
  });

  leg("UPG-24 (the replay exemption is limited to a treasury record at its predecessor) after a completed upgrade (the root moved on) whose restored output is spent again, T1's record is damaged in place (its recorded script hash), so A no longer verifies complete and discovery replays it with T1's record at A's successor but inconsistent and the root beyond A's successor: the Verify never re-writes T1's record over its spent output and leaves A's record unchanged [PIN: holds on 691ebcf]", async (x) => {
    const f = await attributedPartial(x, "upg24", { rootMovesOn: true });
    const before = await upgradeBefore(x, f);
    reversePaymentKeeping(x, f);
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-24 upgrade");
    paymentAcceptedAgain(x, f);
    const v = await x.store.read(C().VAULT, ctx.T1);
    assert.ok(typeof v.live.scriptSha256 === "string" && v.live.scriptSha256.length > 0, "precondition: T1's record carries a script hash");
    v.live.scriptSha256 = "cd".repeat(32);
    await x.store.write(C().VAULT, ctx.T1, v);
    const ver = await wr7().verifyRootActionCompletion(x.config, await x.rootReq(f.A));
    assert.equal(ver.complete, false, `precondition: A no longer verifies complete (${JSON.stringify(ver.missing)})`);
    assert.equal(ver.vault?.position, "SUCCESSOR", "precondition: T1's record is at A's successor");
    const t1Json = await x.recordJson("VAULT", ctx.T1), aJson = JSON.stringify(await x.rootReq(f.A));
    const s = await X_.verifySettled(x);
    const answered = s.result ? JSON.stringify({ root: s.result.root, t1: X_.vaultResult(s.result, ctx.T1) }) : `THROWN ${s.thrown.code} ${s.thrown.message}`;
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, `T1's record is never re-written over its spent output (${answered})`);
    assert.equal(JSON.stringify(await x.rootReq(f.A)), aJson, `A's record is unchanged (${answered})`);
    if (s.result) assert.equal(s.result.root.treasuryUpgrades, undefined, `no upgrade is reported (${answered})`);
  });

  leg("UPG-25 (the upgrade needs A's durable completion verified) after the PARTIAL attribution the root moves on through a hosted T2 AUTHORIZE + pause B2, then B2's record is lost from the store (store damage: the root's recorded history no longer leads back to A, so discovery cannot reach A and A's durable completion no longer verifies), and a reorganization reverses the outside payment (A's T1 successor exact and unspent at depth): the Verify writes nothing, reports no upgrade and T1 stays UNRESOLVED with its record and PARTIAL marker unchanged; with B2's record put back, the next Verify upgrades [PIN: holds on 691ebcf]", async (x) => {
    const f = await attributedPartial(x, "upg25");
    const b2 = await X_.ops.pause(x, ctx.T2, "upg25-pz2");
    assert.equal(x.node.entryAt(f.rootOut), null, "precondition: the root moved on (B2 spent A's root successor)");
    const before = await upgradeBefore(x, f);
    const b2Record = await x.store.read(C().ORG_ROOT_REQUEST, b2.id);
    assert.ok(b2Record, "precondition: B2's record exists");
    await x.store.remove(C().ORG_ROOT_REQUEST, b2.id);
    assert.ok(!(await x.rootReq(b2.id)), "precondition: B2's record is gone");
    const ver = await wr7().verifyRootActionCompletion(x.config, await x.rootReq(f.A));
    assert.equal(ver.complete, false, `precondition: A's durable completion no longer verifies (${JSON.stringify(ver.missing)})`);
    reorgReversesPayment(x, f);
    const r = await writesNothing(x, "the upgrade with A's completion not verified", () => X_.verify(x));
    assert.equal(r.root.treasuryUpgrades, undefined, `no upgrade is reported (${JSON.stringify(r.root.treasuryUpgrades)})`);
    await assertStillUnresolved(x, f, r, before, "UPG-25");
    await x.store.write(C().ORG_ROOT_REQUEST, b2.id, b2Record);
    assert.equal((await wr7().verifyRootActionCompletion(x.config, await x.rootReq(f.A))).complete, true, "with B2's record put back A's durable completion verifies");
    await assertUpgraded(x, f, await X_.verify(x), before, "UPG-25 with B2's record put back");
  });

  leg("CAP-01 (contract D2.2, the candidate cap) A confirmed outside PolicyVault at depth, plus 64 further records on the root's recorded outpoint P each declaring a different root successor address (store clones of A with other transaction ids and root successor scripts; 65 distinct candidate addresses): the Verify answers UNKNOWN with attribution outcome CANDIDATE_CAP (requiredDepthDaa 1000), reads none of the clones' root successor addresses and writes nothing; with one clone removed (exactly 64 distinct candidate addresses) the cap does not apply: the Verify reads each remaining clone's address once and attributes A (ADVANCED FULL) [PIN: holds on 691ebcf]", async (x) => {
    const f = await X_.caseFive(x, "cap01");
    const a = await x.store.read(C().ORG_ROOT_REQUEST, f.A);
    const ri = X_.rootOutIdx(a);
    const spk0 = a.build.frozen.outputs[ri].scriptPublicKey;
    assert.match(String(spk0.scriptHex), /^aa20[0-9a-f]{64}87$/i, "precondition: A's root successor script is a script-hash script");
    const clones = [];
    for (let i = 0; i < 64; i++) {
      const c = structuredClone(a);
      c.id = crypto.randomUUID();
      c.txId = K.hex(`rc45-l201-cap01-tx-${i}`);
      c.build.frozen.outputs[ri].scriptPublicKey = { ...spk0, scriptHex: `aa20${K.hex(`rc45-l201-cap01-root-successor-${i}`)}87` };
      await x.store.write(C().ORG_ROOT_REQUEST, c.id, c);
      clones.push({ id: c.id, address: X_.rootSuccessorAddress(x, c) });
    }
    const addresses = new Set([X_.rootSuccessorAddress(x, a), ...clones.map((c) => c.address)]);
    assert.equal(addresses.size, 65, "precondition: 65 distinct candidate root successor addresses");
    const cloneReads = (from) => {
      const n = new Map(clones.map((c) => [c.address, 0]));
      for (const c of x.node.reads().slice(from)) if (c.method === "getUtxosByAddresses") for (const addr of c.addresses.map(String)) if (n.has(addr)) n.set(addr, n.get(addr) + 1);
      return n;
    };
    const from = x.node.reads().length;
    const r = await writesNothing(x, "65 distinct candidate addresses", () => X_.verify(x));
    X_.assertUnknown(r, "CAP-01 (65)");
    X_.assertAttributionOutcome(r, "CANDIDATE_CAP", { label: "CAP-01 (65)" });
    assert.equal([...cloneReads(from).values()].reduce((s, n) => s + n, 0), 0, "no clone's root successor address is read above the cap");
    assert.equal((await x.rootReq(f.A)).state, "REFUSED", "A is not attributed above the cap");
    const dropped = clones.pop();
    await x.store.remove(C().ORG_ROOT_REQUEST, dropped.id);
    const from2 = x.node.reads().length;
    const r2 = await X_.verify(x);
    X_.assertAttributedAdvanced(r2, f, { label: "CAP-01 (64)" });
    const reads2 = cloneReads(from2);
    for (const c of clones) assert.equal(reads2.get(c.address), 1, `at the cap each remaining clone's root successor address is read exactly once (${c.address}: ${reads2.get(c.address)})`);
  });

  leg("AFT-02b a crash right after the PARTIAL marker save, then T1's original output reappears: the next Verify replays without reading T1 and completes the root PARTIAL (buildable.root true), T1 stays UNRESOLVED and byte-identical, and a root FREEZE builds — never a permanent root refusal [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "aft02b");
    const t1Entry = x.node.entryAt(f.vaultOut);
    await X_.spendT1Successor(x, f.recA);
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === f.A && op.value?.outOfBandAttribution?.mode === "PARTIAL");
    const first = await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, `the Verify reached the PARTIAL marker save (the crash is injected right after it); it answered ${JSON.stringify(first.result?.root ?? first.thrown?.message)}`);
    assert.ok(first.thrown || first.result.root.status !== "ADVANCED", "the crashed Verify does not report ADVANCED");
    const a1 = await x.rootReq(f.A);
    assert.equal(a1.state, "RECONCILIATION_REQUIRED", "A carries the PARTIAL marker, RECONCILIATION_REQUIRED");
    x.node.putEntry(t1Entry.address, t1Entry.entry);
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    const t1succ = X_.vaultSuccessorAddress(x, f.recA), from = x.node.reads().length;
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    assert.equal(r.root.buildable.root, true, "the root is buildable");
    assert.equal(x.node.reads().slice(from).filter((c) => c.method === "getUtxosByAddresses" && c.addresses.includes(t1succ)).length, 0, "a PARTIAL replay never reads T1's successor");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is byte-identical");
    assert.match(String(X_.vaultResult(r, ctx.T1)?.reason), /UNRESOLVED/);
    const b = await X_.rootOnly(x, "freeze", "aft02b-fz");
    assert.equal(b.status, 201, `a root FREEZE builds (${said(b)})`);
  });

  test(`RC45 L2-01 ${backend}: AFT-03 a crash after each durable write of the FULL attributed completion (all later writes fail): the next Verify (even crash points) or Submit on A (odd crash points) completes exactly once — one root and one T1 generation, one receipt, one CHAIN_VERIFIED event line, nothing left holding the root; the first crash point at which no later write fails is the uninterrupted completion (whatever the number of writes), after which the next Verify answers CONSISTENT and writes nothing [RED on 8877dee]`, { skip }, async () => {
    const covered = [];
    for (let k = 1; k <= 24; k++) {
      const x = await X_.fresh(backend);
      try {
        const rootGen0 = Number((await X_.rootRec(x)).generation ?? 0), t1Gen0 = Number((await x.vault(ctx.T1)).generation ?? 0);
        const f = await X_.caseFive(x, `aft03-${k}`);
        const faults = X_.storeFaults(x);
        faults.crashAfter((op, log) => log.length === k);
        const first = await X_.verifySettled(x);
        const interrupted = faults.interrupted(), writes = faults.log().length;
        faults.restore();
        if (!interrupted) {
          /* no write failed: k is at (or past) the completion's last write, so this Verify ran to completion — never a
           * crash point, whatever the parity of the number of writes */
          assert.ok(writes > 0, `the first Verify at depth makes at least one durable write (A's attribution marker); it made ${writes} and answered ${JSON.stringify(first.result?.root ?? first.thrown?.message)}`);
          assert.ok(first.result, `uninterrupted (k = ${k}, ${writes} writes): the Verify returns (${first.thrown?.message})`);
          X_.assertAttributedAdvanced(first.result, f, { label: `uninterrupted (k = ${k}, ${writes} writes)` });
          const next = await writesNothing(x, `the Verify after the completed Verify (k = ${k})`, () => X_.verify(x));
          assert.equal(next.root.status, "CONSISTENT", `uninterrupted (k = ${k}): the next Verify answers CONSISTENT, never a second ADVANCED (${next.root.status} ${next.root.via ?? ""})`);
          await X_.assertCompletedOnce(x, f, `uninterrupted (k = ${k})`);
          assert.equal((await x.rootReq(f.A)).state, "CHAIN_VERIFIED");
          assert.equal(Number((await X_.rootRec(x)).generation ?? 0), rootGen0 + 1, `uninterrupted (k = ${k}): exactly one root generation`);
          assert.equal(Number((await x.vault(ctx.T1)).generation ?? 0), t1Gen0 + 1, `uninterrupted (k = ${k}): exactly one T1 generation`);
          assert.equal((await X_.rootRec(x)).pendingRequestId, null, `uninterrupted (k = ${k}): nothing holds the root`);
          covered.push({ k, uninterrupted: true, writes });
          break;
        }
        const viaSubmit = k % 2 === 1;
        if (viaSubmit) {
          const sub = await KK.NODE().with(x.node.rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", f.A, "submit"], {}, x.cookie.o1));
          assert.equal(sub.status, 200, `crash after write ${k}: Submit on A completes it (${said(sub)})`);
          assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
          const r = await X_.verify(x);
          assert.equal(r.root.status, "CONSISTENT", `crash after write ${k}: a Verify after the Submit answers CONSISTENT`);
        } else {
          const r = await X_.verify(x);
          X_.assertAttributedAdvanced(r, f, { label: `the Verify after a crash after write ${k}`, replay: true });
        }
        await X_.assertCompletedOnce(x, f, `crash after write ${k}`, { via: ["attribution", "reconcile", "submit-recovery"] });
        assert.equal((await x.rootReq(f.A)).state, "CHAIN_VERIFIED");
        assert.equal(Number((await X_.rootRec(x)).generation ?? 0), rootGen0 + 1, `crash after write ${k}: exactly one root generation`);
        assert.equal(Number((await x.vault(ctx.T1)).generation ?? 0), t1Gen0 + 1, `crash after write ${k}: exactly one T1 generation`);
        assert.equal((await X_.rootRec(x)).pendingRequestId, null, `crash after write ${k}: nothing holds the root`);
        covered.push({ k, viaSubmit });
      } finally { await X_.release(x); }
    }
    assert.ok(covered.some((c) => c.uninterrupted), "every crash point of the completion was covered");
  });

  leg("AFT-03b (after the vault write) a crash right after the FULL T1 write, then T1's new output is spent outside PolicyVault: the next Verify completes FULL on the root without reading or re-adopting T1, nothing holds the root, and a T1 build is refused 409 RECORDED_OUTPUT_SPENT [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "aft03b1");
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().VAULT && op.key === ctx.T1);
    await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, "the Verify reached the FULL T1 write (the crash is injected right after it)");
    const t1 = await x.vault(ctx.T1);
    assert.ok(sameOp(t1.live.outpoint, f.vaultOut), "T1 was written at A's successor before the crash");
    KK.outOfAppAgentSpend(x, { template: t1.template, state: f.recA.build.successorState, outpoint: f.vaultOut, covenantId: t1.live.covenantId, registry: f.recA.newRegistry, delegate: ctx.w.n1, recipient: ctx.w.recipient.xonly });
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    /* T1's successor address is also T1's recorded address now, so every Verify's own treasury pass reads it; the replay
     * itself (attribution and completion) must add no read of it */
    const t1succ = X_.vaultSuccessorAddress(x, f.recA);
    const t1Reads = (from) => x.node.reads().slice(from).filter((c) => c.method === "getUtxosByAddresses" && c.addresses.includes(t1succ)).length;
    const from = x.node.reads().length;
    const r = await X_.verify(x);
    const replayReads = t1Reads(from);
    X_.assertAttributedAdvanced(r, f, { mode: "FULL" });
    assert.equal((await x.rootReq(f.A)).outOfBandAttribution.mode, "FULL", "no mode change when T1 is not at its predecessor");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is not re-written");
    assert.equal(r.root.buildable.root, true, "nothing holds the root");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
    const from2 = x.node.reads().length;
    const r2 = await X_.verify(x);
    assert.equal(r2.root.status, "CONSISTENT", `the Verify after the replay answers the root CONSISTENT (${r2.root.status})`);
    const ordinaryReads = t1Reads(from2);
    assert.ok(replayReads <= ordinaryReads, `the replay reads T1's successor address no more often than an ordinary Verify's treasury pass does (replay ${replayReads}, ordinary ${ordinaryReads}): it never reads T1`);
    await refused(x, "a T1 build after its output was spent", () => X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "aft03b1-pz"), 409, "RECORDED_OUTPUT_SPENT");
  });

  leg("AFT-03b (before the vault write) a crash right after the FULL marker save, then T1's new output is spent outside PolicyVault: the next Verify downgrades the replay to PARTIAL in one save (mode PARTIAL, modeChangedAt, treasury.state UNRESOLVED), never writes T1 and completes the root; nothing holds the root [RED on 8877dee]", async (x) => {
    const t1Json = await x.recordJson("VAULT", ctx.T1);
    const f = await X_.caseFive(x, "aft03b2");
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === f.A && op.value?.outOfBandAttribution?.mode === "FULL");
    await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, "the Verify reached the FULL marker save (the crash is injected right after it)");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 not yet written");
    await X_.spendT1Successor(x, f.recA);
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { mode: "PARTIAL" });
    const m = (await x.rootReq(f.A)).outOfBandAttribution;
    assert.equal(m.mode, "PARTIAL");
    assert.ok(typeof m.modeChangedAt === "string" && m.modeChangedAt.length > 0, "modeChangedAt is recorded");
    assert.equal(m.treasury.state, "UNRESOLVED", "the same save records T1 UNRESOLVED");
    assert.equal(await x.recordJson("VAULT", ctx.T1), t1Json, "T1 is never written");
    assert.equal(r.root.buildable.root, true);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
  });

  leg("REPLAY wording: a crash after the root record advanced to A's successor (before A is CHAIN_VERIFIED); the next Verify replays the bound marker through discovery and answers ADVANCED with the attribution fields (via attribution, mode, requestId A, holds, buildable), never the generic replay answer [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "replay");
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT && op.value?.live && sameOp(op.value.live.outpoint, f.rootOut));
    await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, "the Verify reached the root write (the crash is injected right after it)");
    assert.ok(sameOp((await X_.rootRec(x)).live.outpoint, f.rootOut), "the root record already follows A's successor");
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f, { label: "the discovery replay", replay: true });
    assert.ok(Array.isArray(r.root.holds), "holds is answered");
    assert.equal(r.root.buildable?.root, true, "buildability is answered from the records");
    await X_.assertCompletedOnce(x, f, "A", { via: ["attribution", "reconcile"] });
  });

  /* =============================== REG-04: unmarked callers unchanged =============================== */
  leg("REG-04 unmarked records keep C3's rules: an unmarked withdrawn request without a final transaction never completes from chain evidence (completeProvenRootAction refuses its binding, writing nothing), stays never-effective without submission evidence (also as AUTHORIZED and as a legacy RECONCILIATION_REQUIRED draft), and discovery skips it when its transaction is the root's live one (CONSISTENT, nothing written) [PIN: holds on 8877dee]", async (x) => {
    const recA = await X_.caseFiveA(x, "reg04");
    KK.confirmOutOfBand(x, recA);
    const target = { rootOutIndex: X_.rootOutIdx(recA), rootAddress: X_.rootSuccessorAddress(x, recA), rootExpectedValue: String(recA.build.frozen.outputs[X_.rootOutIdx(recA)].value) };
    await writesNothing(x, "completion of an unmarked draft", async () => {
      /* the refusal itself is pinned, never its wording: C3 refuses because the missing final transaction cannot be
       * normalized; C4's binding dispatch (no final transaction, no in-memory attribution, no bound marker) may refuse
       * with its own message or code */
      await assert.rejects(wr7().completeProvenRootAction(x.config, recA, { ...target, rpc: x.node.rpc, via: "reconcile" }), (e) => {
        assert.ok(e instanceof Error, `an Error is thrown (${e})`);
        assert.ok(!["TypeError", "ReferenceError", "RangeError", "SyntaxError"].includes(e.name), `a deliberate refusal, never a crash (${e.name}: ${e.message})`);
        assert.notEqual(e.code, "TEST_CRASH");
        return true;
      });
    });
    assert.equal((await x.rootReq(recA.id)).state, "REFUSED", "the unmarked draft is not completed");
    assert.equal(await X_.receiptOf(x, lower(recA.txId)), null, "no receipt for the draft's txid");
    for (const [label, q] of [["REFUSED", recA], ["AUTHORIZED", { ...recA, state: "AUTHORIZED" }], ["legacy RECONCILIATION_REQUIRED draft", { ...recA, state: "RECONCILIATION_REQUIRED" }]]) {
      assert.equal(wr7().neverEffective(q), true, `${label}: never effective`);
      assert.equal(wr7().hasSubmissionEvidence(q), false, `${label}: no submission evidence`);
    }
    /* the root record (by store edit) names A's root successor as its live outpoint: discovery must skip the draft */
    const root = await x.store.read(C().ORG_ROOT, ctx.rootId);
    root.live = { ...root.live, outpoint: X_.rootSuccessorOutpoint(recA), address: target.rootAddress, value: target.rootExpectedValue };
    await x.store.write(C().ORG_ROOT, ctx.rootId, root);
    const r = await writesNothing(x, "Verify with an unmarked draft on the live transaction", () => X_.verify(x));
    assert.equal(r.root.status, "CONSISTENT", `discovery skips the never-effective draft (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal((await x.rootReq(recA.id)).state, "REFUSED");
  });
}
