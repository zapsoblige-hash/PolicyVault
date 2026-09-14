"use strict";
/*
 * SDK / CRASH-RECOVERY — RC35-RES-01 (independent RC35 affected review, 2026-09-11; owner repair directive of the same day).
 *
 * The reviewer's finding (exact-image storage check headless-reservation.json): the headless v0.1 / v0.2 creators
 * persisted only a submission claim keyed by txid, which the identity scan never read, so after a crash or a plain
 * restart a live claim coexisted with a vault identity that looked free — a sequential-restart defect even within the
 * documented single-writer model.
 *
 * These regressions drive the REAL headless creators (sdk/src/create-vault.js, sdk/src/vault-ops-v2.js — the whole
 * build / sign / record / claim / broadcast / observation / create-only completion flow, with the real WASM transaction
 * generator and real signatures) against an in-process mock node (TEST keys; nothing leaves the process). They prove:
 * the durable headless creation record binds the identity to the creator and the exact expected outcome BEFORE any
 * chain effect; a lost response keeps the claim AND the identity reserved (both phases) — also in a FRESH PROCESS on the
 * same data root; the same creation completes by observation only (no rebroadcast; identical txid / signed bytes); a
 * genuine rejection settles with proof and releases the claim while the identity stays reserved for new creations
 * (never recycled); fresh identities keep working; a LEGACY retained claim (written by an earlier runtime without a
 * record) reserves the identity, is listed, and can be completed only from the ORIGINAL definition — with the
 * covenant id read from the chain — while a mismatched definition is refused and an unobserved output leaves the claim
 * exactly as it is. REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) without silverc / the encoder.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { loadConfig } = require("../src/config");
const { getStore, Categories } = require("../src/store");
const { findVaultIdentityReservation, assertVaultIdentityFree } = require("../src/vault-identity");
const { createVault } = require("../src/create-vault");
const { createVaultV2 } = require("../src/vault-ops-v2");
const headless = require("../src/headless-creation");
const { claimSubmission } = require("../src/submission-claim");
const { toolchainSkip, answers } = require("./helpers/rc35-recovery-fixtures");
const { negativeRpc } = require("./helpers/negative-proof-fixtures");

const SKIP = toolchainSkip("pv-res01-probe-");
const KAS = 100000000n;
const hex32 = () => crypto.randomBytes(32).toString("hex");

/* a mock node in the shape the WASM transaction generator and the SDK's UTXO reader both accept */
function nodeMock(cfg) {
  const kaspa = require(cfg.rustyKaspaModule);
  const table = {};
  const rpc = {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    fund(address, xonly, amount) { table[address] = [...(table[address] ?? []), { address, outpoint: { transactionId: hex32(), index: 0 }, amount, scriptPublicKey: { version: 0, script: `20${xonly}ac` }, blockDaaScore: 1n, isCoinbase: false }]; },
    seedVault(address, txId, index, amount, covenantId) { table[address] = [...(table[address] ?? []), { address, outpoint: { transactionId: txId, index }, amount, scriptPublicKey: { version: 0, script: "" }, blockDaaScore: 2n, isCoinbase: false, covenantId }]; },
    clear(address) { table[address] = []; }
  };
  return { kaspa, rpc, connection: { rpc, kaspa, serverInfo: { networkId: cfg.networkId } } };
}
function keyOf(kaspa, byte, networkId) {
  const secret = byte.toString(16).padStart(2, "0").repeat(32);
  const priv = new kaspa.PrivateKey(secret);
  return { secret, address: priv.toPublicKey().toAddress(networkId).toString(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase() };
}
function setup(t) {
  const cfg = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-res01-")) });
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const { kaspa, rpc, connection } = nodeMock(cfg);
  const funder = keyOf(kaspa, 0xf0, cfg.networkId), owner = keyOf(kaspa, 0x21, cfg.networkId), delegate = keyOf(kaspa, 0x62, cfg.networkId), r1 = keyOf(kaspa, 0x63, cfg.networkId);
  rpc.fund(funder.address, funder.xonly, 5000n * KAS);
  const store = getStore(cfg);
  const policyFor = (vaultId) => ({ label: "headless v1", owner: owner.xonly, delegate: delegate.xonly, vaultId, maxPerSpend: (10n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "600", recipients: [r1.xonly], initValue: (100n * KAS).toString(), initPeriodStartDaa: "1000" });
  const v2For = (vaultId) => ({ templateInput: { owner: owner.xonly, vaultId }, initialStateInput: { protectedValue: (100n * KAS).toString(), periodStartDaa: "1000", periodSpent: "0", paused: "0", delegate: delegate.xonly, maxPerSpend: (10n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "600", recipients: [r1.xonly], delegateActive: "1", policyNonce: "0" } });
  const drivers = {
    v1: (vaultId, over = {}) => createVault({ config: cfg, policyInput: policyFor(vaultId), fundingKey: { secret: funder.secret, address: funder.address }, delegateAddress: delegate.address, delegateFuelSompi: 0n, connection: over.connection ?? connection, pollAttempts: 1, pollDelayMs: 0 }),
    v2: (vaultId, over = {}) => createVaultV2({ config: cfg, ...v2For(vaultId), fundingKey: { secret: funder.secret, address: funder.address }, delegateFuelSompi: 0n, label: "headless v2", connection: over.connection ?? connection, pollAttempts: 1, pollDelayMs: 0 })
  };
  /* a node view whose broadcast answers follow a script and which lands the vault output when told to */
  function scripted(answerFor) {
    const s = { calls: 0 };
    s.rpc = { ...rpc, async submitTransaction({ transaction }) { s.calls += 1; const txId = transaction.finalize().toString().toLowerCase(); const a = answerFor(txId, transaction); if (a && a.land) landOutput(transaction, txId); if (a && a.throw) throw new Error(a.throw); return { transactionId: txId }; } };
    // Authoritative original anchor, complete acceptance window, exact funding and all-pools mempool miss.
    s.rpc = negativeRpc(cfg, null, { baseRpc: s.rpc, captureAtSubmission: true }).rpc;
    s.connection = { rpc: s.rpc, kaspa, serverInfo: { networkId: cfg.networkId } };
    return s;
  }
  /* land the vault output of a signed transaction exactly as the node would index it */
  function landOutput(transaction, txId) {
    const outs = transaction.outputs;
    for (let i = 0; i < outs.length; i++) {
      const o = outs[i];
      if (!o.covenant) continue;
      const addr = kaspa.addressFromScriptPublicKey(o.scriptPublicKey, cfg.networkId).toString();
      rpc.seedVault(addr, txId, i, BigInt(o.value), String(o.covenant.covenantId).toLowerCase());
    }
  }
  return { cfg, kaspa, rpc, connection, store, funder, owner, delegate, r1, policyFor, v2For, drivers, scripted, landOutput };
}

for (const generation of ["v1", "v2"]) {
  test(`RES-01 (${generation}): a headless creation writes its durable record BEFORE the claim and the broadcast; a LOST response keeps the claim and reserves the identity in both phases — also in a FRESH PROCESS — and the same creation completes by observation only (no rebroadcast, identical txid / signed bytes); fresh identities keep working`, { skip: SKIP }, async (t) => {
    const x = await setup(t);
    const vaultId = hex32();
    /* the broadcast is accepted by the node (the output lands) but the response is lost */
    const s = x.scripted(() => ({ land: true, throw: answers.transportLost() }));
    await assert.rejects(() => x.drivers[generation](vaultId, { connection: s.connection }), /not observed|reconcile|recover/i);
    assert.equal(s.calls, 1);
    const records = await headless.listHeadlessCreations(x.cfg, { vaultId });
    assert.equal(records.length, 1, "exactly one durable headless creation record");
    const rec = records[0];
    assert.equal(rec.schema, headless.HEADLESS_CREATION_SCHEMA);
    assert.equal(rec.state, "RECONCILIATION_REQUIRED");
    assert.equal(rec.creator, x.funder.address, "bound to the authorized creation identity");
    assert.equal(rec.generation, generation);
    assert.match(rec.txId, /^[0-9a-f]{64}$/);
    assert.equal(typeof rec.signedSafeJson, "string");
    assert.equal(rec.expected.value, (100n * KAS).toString());
    const claim = await x.store.read(Categories.SUBMISSION_CLAIM, rec.txId);
    assert.ok(claim, "the submission claim is held");
    assert.equal(claim.vaultId, vaultId);
    assert.equal(await x.store.read(Categories.VAULT, vaultId), null, "no vault record before proof");
    /* the identity is reserved — build phase and commit phase — in THIS process */
    assert.deepEqual(await findVaultIdentityReservation(x.cfg, vaultId), { kind: "REQUEST" });
    assert.deepEqual(await findVaultIdentityReservation(x.cfg, vaultId, { phase: "commit" }), { kind: "REQUEST" });
    await assert.rejects(() => assertVaultIdentityFree(x.cfg, vaultId), (e) => e.code === "VAULT_ID_IN_USE");
    await assert.rejects(() => x.drivers[generation](vaultId), (e) => e.code === "VAULT_ID_IN_USE", "a new creation under the same identity is refused before anything is built");
    /* ... and in a FRESH PROCESS on the same data root (the reviewer's restart check) */
    const child = JSON.parse(execFileSync(process.execPath, ["-e", `
      const { loadConfig } = require(${JSON.stringify(path.join(__dirname, "..", "src", "config"))});
      const VI = require(${JSON.stringify(path.join(__dirname, "..", "src", "vault-identity"))});
      const { getStore, Categories } = require(${JSON.stringify(path.join(__dirname, "..", "src", "store"))});
      (async () => {
        const config = loadConfig({ dataRoot: ${JSON.stringify(x.cfg.dataRoot)} });
        let refusal = null; try { await VI.assertVaultIdentityFree(config, ${JSON.stringify(vaultId)}); } catch (e) { refusal = e.code; }
        console.log(JSON.stringify({ build: await VI.findVaultIdentityReservation(config, ${JSON.stringify(vaultId)}), commit: await VI.findVaultIdentityReservation(config, ${JSON.stringify(vaultId)}, { phase: "commit" }), refusal, claim: !!await getStore(config).read(Categories.SUBMISSION_CLAIM, ${JSON.stringify(rec.txId)}) }));
      })().catch((e) => { console.error(e.stack); process.exit(1); });
    `], { encoding: "utf8", env: { ...process.env, TMPDIR: process.env.TMPDIR ?? os.tmpdir() } }).trim().split("\n").pop());
    assert.deepEqual(child.build, { kind: "REQUEST" }, "fresh process: build-phase reservation");
    assert.deepEqual(child.commit, { kind: "REQUEST" }, "fresh process: commit-phase reservation");
    assert.equal(child.refusal, "VAULT_ID_IN_USE");
    assert.equal(child.claim, true);
    /* observation-only recovery through the same record (the output landed on the node) */
    const dark = x.scripted(() => ({ throw: answers.transportLost() }));
    const out = await headless.recoverHeadlessCreation(x.cfg, { requestId: rec.requestId, rpc: dark.rpc });
    assert.equal(dark.calls, 0, "recovery never broadcasts");
    assert.equal(out.outcome, "CHAIN_VERIFIED", out.detail);
    assert.equal(out.record.txId, rec.txId);
    assert.equal(out.record.signedSafeJson, rec.signedSafeJson);
    const vault = await x.store.read(Categories.VAULT, vaultId);
    assert.ok(vault, "the vault record was created by observation");
    assert.equal(vault.creationTxId, rec.txId);
    assert.equal(vault.live.covenantId, rec.expected.covenantId);
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, rec.txId), null, "released by chain proof");
    assert.equal((await x.store.read(Categories.RECEIPT, rec.txId)).vaultId, vaultId);
    assert.deepEqual(await findVaultIdentityReservation(x.cfg, vaultId), { kind: "VAULT_RECORD", readable: true });
    /* idempotent replay */
    const again = await headless.recoverHeadlessCreation(x.cfg, { requestId: rec.requestId, rpc: dark.rpc });
    assert.equal(again.outcome, "CHAIN_VERIFIED");
    assert.equal(dark.calls, 0);
    /* a FRESH identity still creates end to end (accepted response, output lands) */
    const fresh = hex32();
    const ok = x.scripted(() => ({ land: true }));
    const created = await x.drivers[generation](fresh, { connection: ok.connection });
    assert.equal(ok.calls, 1);
    assert.equal(created.manifest.vaultId, fresh);
    assert.equal((await headless.listHeadlessCreations(x.cfg, { vaultId: fresh }))[0].state, "CHAIN_VERIFIED");
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, created.txId), null);
  });

  test(`RES-01 (${generation}): a GENUINE rejection settles with the output verified absent (claim released, proof recorded) while the identity stays reserved for new creations (never recycled); an already-accepted answer is observed like an accepted response; an unresolved creation stays protected when unobserved`, { skip: SKIP }, async (t) => {
    const x = await setup(t);
    const rejectedId = hex32();
    const s = x.scripted((txId) => ({ throw: answers.nonStandard(txId) }));
    await assert.rejects(() => x.drivers[generation](rejectedId, { connection: s.connection }), (e) => e.code === "SUBMISSION_REJECTED");
    const rec = (await headless.listHeadlessCreations(x.cfg, { vaultId: rejectedId }))[0];
    assert.equal(rec.state, "SUBMISSION_REJECTED");
    assert.equal(rec.submissionOutcome.proof.outputsAbsent, true);
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, rec.txId), null, "a proven negative releases the claim");
    assert.deepEqual(await findVaultIdentityReservation(x.cfg, rejectedId), { kind: "REQUEST" }, "identities are never recycled");
    assert.equal(await findVaultIdentityReservation(x.cfg, rejectedId, { phase: "commit" }), null, "an established negative does not block a sibling at commit time");
    await assert.rejects(() => x.drivers[generation](rejectedId), (e) => e.code === "VAULT_ID_IN_USE");
    const keep = await headless.recoverHeadlessCreation(x.cfg, { requestId: rec.requestId, rpc: s.rpc });
    assert.equal(keep.outcome, "SUBMISSION_REJECTED", "an established negative stays as it is");
    assert.equal(s.calls, 1);
    /* already accepted: observed like an accepted response */
    const acceptedId = hex32();
    const a = x.scripted((txId) => ({ land: true, throw: answers.alreadyAccepted(txId) }));
    const created = await x.drivers[generation](acceptedId, { connection: a.connection });
    assert.equal(a.calls, 1);
    assert.equal(created.manifest.vaultId, acceptedId);
    const arec = (await headless.listHeadlessCreations(x.cfg, { vaultId: acceptedId }))[0];
    assert.equal(arec.state, "CHAIN_VERIFIED");
    assert.equal(arec.submissionResponse.kind, "ALREADY_KNOWN");
    /* unresolved and unobserved: protected (claim kept), nothing rebroadcast */
    const pendingId = hex32();
    const p = x.scripted(() => ({ throw: answers.transportLost() }));
    await assert.rejects(() => x.drivers[generation](pendingId, { connection: p.connection }));
    const prec = (await headless.listHeadlessCreations(x.cfg, { vaultId: pendingId }))[0];
    const still = await headless.recoverHeadlessCreation(x.cfg, { requestId: prec.requestId, rpc: p.rpc });
    assert.equal(still.outcome, "PENDING");
    assert.equal(p.calls, 1);
    assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, prec.txId));
    assert.equal((await headless.loadHeadlessCreation(x.cfg, prec.requestId)).state, "RECONCILIATION_REQUIRED");
  });
}

test("RES-01 (legacy retained claim): a submission claim written by an earlier runtime WITHOUT a record reserves the identity in both phases (also after a fresh process), is listed as needing the original definition, refuses a mismatched definition, leaves an unobserved claim exactly as it is, and completes from the ORIGINAL definition with the covenant id read from the chain", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const vaultId = hex32();
  const txId = hex32();
  /* the pre-correction runtime's only durable trace: the claim keyed by txid, naming the identity */
  await claimSubmission(x.cfg, { txId, vaultId, action: "createVault" });
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, vaultId), { kind: "SUBMISSION_CLAIM", txId, action: "createVault" });
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, vaultId, { phase: "commit" }), { kind: "SUBMISSION_CLAIM", txId, action: "createVault" });
  await assert.rejects(() => assertVaultIdentityFree(x.cfg, vaultId), (e) => e.code === "VAULT_ID_IN_USE");
  await assert.rejects(() => x.drivers.v1(vaultId), (e) => e.code === "VAULT_ID_IN_USE", "a new headless creation under the claimed identity is refused before anything is built");
  const child = JSON.parse(execFileSync(process.execPath, ["-e", `
    const { loadConfig } = require(${JSON.stringify(path.join(__dirname, "..", "src", "config"))});
    const VI = require(${JSON.stringify(path.join(__dirname, "..", "src", "vault-identity"))});
    (async () => { const config = loadConfig({ dataRoot: ${JSON.stringify(x.cfg.dataRoot)} }); console.log(JSON.stringify({ build: await VI.findVaultIdentityReservation(config, ${JSON.stringify(vaultId)}), commit: await VI.findVaultIdentityReservation(config, ${JSON.stringify(vaultId)}, { phase: "commit" }) })); })().catch((e) => { console.error(e.stack); process.exit(1); });
  `], { encoding: "utf8" }).trim().split("\n").pop());
  assert.equal(child.build.kind, "SUBMISSION_CLAIM", "fresh process: the legacy claim reserves the identity");
  assert.equal(child.commit.kind, "SUBMISSION_CLAIM");
  /* listed as unresolved, needing the original definition */
  const unresolved = await headless.listUnresolvedHeadlessClaims(x.cfg);
  assert.deepEqual(unresolved.map((u) => ({ txId: u.txId, vaultId: u.vaultId, disposition: u.disposition })), [{ txId, vaultId, disposition: "NEEDS_ORIGINAL_DEFINITION" }]);
  /* nothing is inferred: without the definition, refused; with a definition naming another identity, refused */
  await assert.rejects(() => headless.recoverLegacyHeadlessClaim(x.cfg, { txId, rpc: x.rpc }), (e) => e.code === "DEFINITION_REQUIRED");
  await assert.rejects(() => headless.recoverLegacyHeadlessClaim(x.cfg, { txId, policyInput: x.policyFor(hex32()), rpc: x.rpc }), (e) => e.code === "DEFINITION_MISMATCH");
  /* the original definition, output not observed: the claim stays exactly as it is */
  const policyInput = x.policyFor(vaultId);
  const notYet = await headless.recoverLegacyHeadlessClaim(x.cfg, { txId, policyInput, rpc: x.rpc });
  assert.equal(notYet.outcome, "UNRESOLVED");
  assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, txId), "the claim is untouched");
  assert.equal((await headless.listHeadlessCreations(x.cfg, { vaultId })).length, 0, "no record is written for an unobserved claim");
  /* the output IS on the chain: derive the address from the original definition, read the covenant id from the observed output */
  const { compileExactState } = require("../src/contract-compiler");
  const { normalizePolicy, normalizeState } = require("../src/vault-state");
  const { covenantAddress } = require("../src/chain");
  const policy = normalizePolicy(policyInput);
  const compiled = compileExactState({ config: x.cfg, policy, state: normalizeState({ protectedValue: policy.initValue, periodStartDaa: policy.initPeriodStartDaa, periodSpent: "0", paused: "0" }) });
  const address = covenantAddress(x.cfg, compiled.scriptBytes);
  const observedCovenantId = hex32();
  x.rpc.seedVault(address, txId, 1, policy.initValue, observedCovenantId);
  const done = await headless.recoverLegacyHeadlessClaim(x.cfg, { txId, policyInput, rpc: x.rpc });
  assert.equal(done.outcome, "CHAIN_VERIFIED", done.detail);
  const vault = await x.store.read(Categories.VAULT, vaultId);
  assert.equal(vault.creationTxId, txId);
  assert.equal(vault.live.covenantId, observedCovenantId, "the covenant id is read from the chain, never guessed");
  assert.equal(vault.live.outpoint.index, 1);
  assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, txId), null, "released by chain proof");
  assert.equal((await headless.listHeadlessCreations(x.cfg, { vaultId }))[0].state, "CHAIN_VERIFIED");
  assert.deepEqual(await headless.listUnresolvedHeadlessClaims(x.cfg), []);
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, vaultId), { kind: "VAULT_RECORD", readable: true });
});
