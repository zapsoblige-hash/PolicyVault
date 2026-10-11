"use strict";
/*
 * RC45 R2 test support: v0.7-kas records written by the pinned RC44 (df5b8de)
 * writers, for the strand-rule legs of the delegate period-start suites.
 * Internal RED-first regression material; not an audit.
 *
 * RC44 commits a delegate's period start exactly as requested and never
 * re-checks it before signing or broadcasting. The commit-time freshness suite needs, exactly
 * as RC44 wrote them, the two kinds of SIGNED records that the period-start
 * rule deliberately does NOT refuse at submit (a refusal there would strand the
 * organization root or the creation; they are the stated residual counted at
 * activation):
 *   - a SIGNED rooted-KAS treasury creation whose delegate starts at 0;
 *   - a SIGNED (finalized), never-attempted organization-root request carrying
 *     a v0.7-kas ownerSetAgentRoot that adds a delegate starting at 0.
 * Both ride ONE organizational root (owners 0x71 / 0x72 / 0x73, 2-of-3, the
 * same TEST keys the candidate suites sign in with) whose own genesis, and the
 * genesis of the treasury the delegate-rule change modifies, are driven to
 * CHAIN_VERIFIED against an in-child mock chain.
 *
 * The parent (a candidate test) never loads an RC44 module. It verifies the
 * read-only extraction named by POLICYVAULT_TEST_RC44_TREE (the writer sha256
 * pins and the df5b8de sdk/src git tree of rc45-rc44-history.js; a missing or
 * mismatched tree FAILS, never skips), builds the test-local overlay of
 * rc45-rc44-history.js (byte copies of the RC44 sdk/src, core and contracts,
 * links to the remaining RC44 directories and dependencies and to this tree's
 * pv_* VM binaries) and runs THIS file as a child process that loads ONLY the
 * overlay's RC44 modules and writes a JSON data root. The parent reads it
 * through the candidate store.
 *
 * TEST keys only; every config names ws://127.0.0.1:1, so nothing can dial a
 * node; no production data.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const H44 = require("./rc45-rc44-history");

const RESULT_TAG = "RC45-R2-KAS-RC44-WRITER-RESULT ";

/* ---------------- child side (RC44 modules only) ---------------- */
async function child({ overlay, dataRoot, input }) {
  H44.verifyRc44Tree(overlay);
  const src = path.join(overlay, "sdk", "src");
  const r = (name) => require(path.join(src, name));
  const config = r("config.js").loadConfig({ dataRoot, rpcUrl: H44.LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const wr7 = r("wallet-requests-v7.js"), wr7kas = r("wallet-requests-v7-kas.js"), chain = r("chain.js");
  const kaspa = chain.loadKaspa(config);
  const KAS = H44.KAS;
  const wallet = (byte) => { const key = new kaspa.PrivateKey(byte.toString(16).padStart(2, "0").repeat(32)); return { key, xonly: key.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: key.toPublicKey().toAddress(config.networkId).toString() }; };
  const o1 = wallet(0x71), o2 = wallet(0x72), o3 = wallet(0x73), fee = wallet(0x64), recovery = wallet(0x51);
  const utxo = (w, tag, amountKas) => ({ outpoint: { transactionId: require("node:crypto").createHash("sha256").update(`rc45-r2-kas-rc44-${tag}`).digest("hex"), index: 0 }, amount: (BigInt(amountKas) * KAS).toString(), scriptPublicKeyHex: `20${w.xonly}ac` });
  const signAll = (unsignedSafeJson, list, w) => { const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson); const ins = tx.inputs; for (const s of list) ins[s.index].signatureScript = kaspa.createInputSignature(tx, s.index, w.key); tx.inputs = ins; return tx.serializeToSafeJSON(); };
  /* the in-child mock chain: a frozen transaction's effect appears only when that exact transaction is broadcast */
  const table = new Map(), effects = new Map();
  const spkAddress = (spk) => kaspa.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
  const rpc = {
    async getBlockDagInfo() { return { virtualDaaScore: String(input.daa), sink: "3a".repeat(32) }; },
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses.map(String)) for (const e of table.get(a) ?? []) entries.push({ address: a, outpoint: { ...e.outpoint }, utxoEntry: { amount: e.amount.toString(), scriptPublicKey: { version: 0, script: "" }, covenantId: e.covenantId ?? undefined, blockDaaScore: String(input.daa), isCoinbase: false } }); return { entries }; },
    async submitTransaction({ transaction }) { const id = transaction.finalize().toString().toLowerCase(); const fx = effects.get(id); if (fx) fx(); return { transactionId: id }; },
    async getMempoolEntry() { throw new Error("not found"); },
    async disconnect() {}
  };
  const expect = (frozen, txId) => effects.set(txId, () => {
    for (const i of frozen.inputs) for (const [a, es] of table) table.set(a, es.filter((e) => !(e.outpoint.transactionId === i.previousOutpoint.transactionId && e.outpoint.index === i.previousOutpoint.index)));
    frozen.outputs.forEach((o, i) => { const a = spkAddress(o.scriptPublicKey); table.set(a, [...(table.get(a) ?? []), { outpoint: { transactionId: txId, index: i }, amount: BigInt(o.value), covenantId: o.covenant ? o.covenant.covenantId : null }]); });
  });

  /* the root (CHAIN_VERIFIED) */
  const rootReq = await wr7.buildRootGenesisRequest({ config, label: "RC45 R2 TEST rc44 root", owners: [{ slot: 1, publicKey: o1.xonly }, { slot: 2, publicKey: o2.xonly }, { slot: 3, publicKey: o3.xonly }], ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: o1.address, funding: [utxo(o1, "root", 20n)] });
  const rootSigned = await wr7.submitOrgRootRequestSignature({ config, requestId: rootReq.id, signedSafeJson: signAll(rootReq.transaction.unsignedSafeJson, rootReq.transaction.signInputs, o1) });
  expect(rootSigned.build.frozen, rootSigned.txId);
  assert.equal((await wr7.submitOrgRootRequest({ config, requestId: rootReq.id, rpc, pollAttempts: 1, pollDelayMs: 0 })).state, "CHAIN_VERIFIED");
  const rootId = rootReq.rootCovenantId;

  /* the treasury the delegate-rule change modifies (CHAIN_VERIFIED) */
  const tReq = await wr7kas.buildKasVaultGenesisRequest({ config, rootCovenantId: rootId, label: "RC45 R2 TEST rc44 treasury", agents: input.installed, approvers: [], approvalM: 0, recoveryAddress: recovery.address, depositKas: "100", feeReserveKas: "5", signerAddress: o1.address, funding: [utxo(o1, "treasury", 200n)], vaultId: input.treasuryVaultId });
  const tSigned = await wr7kas.finalizeKasWalletRequest({ config, requestId: tReq.requestId, signedSafeJson: signAll(tReq.transaction.unsignedSafeJson, tReq.transaction.signInputs, o1) });
  expect(tSigned.build.frozen, tSigned.txId);
  assert.equal((await wr7kas.submitKasWalletRequest({ config, requestId: tReq.requestId, rpc, pollAttempts: 1, pollDelayMs: 0 })).state, "CHAIN_VERIFIED");

  /* a SIGNED treasury creation whose delegate starts at 0 (never submitted) */
  const gReq = await wr7kas.buildKasVaultGenesisRequest({ config, rootCovenantId: rootId, label: "RC45 R2 TEST rc44 signed creation", agents: input.creationAgents, approvers: [], approvalM: 0, recoveryAddress: recovery.address, depositKas: "10", feeReserveKas: "1", signerAddress: o1.address, funding: [utxo(o1, "creation", 200n)], vaultId: input.creationVaultId });
  const gSigned = await wr7kas.finalizeKasWalletRequest({ config, requestId: gReq.requestId, signedSafeJson: signAll(gReq.transaction.unsignedSafeJson, gReq.transaction.signInputs, o1) });
  assert.equal(gSigned.state, "SIGNED");

  /* a SIGNED, never-attempted root request carrying ownerSetAgentRoot (a new delegate at start 0) */
  const op = await wr7.buildRootActionRequest({ config, rootCovenantId: rootId, action: "authorize", params: { fuel: utxo(fee, "fee", 50n) }, vaultOperations: [{ vaultId: input.treasuryVaultId, action: "ownerSetAgentRoot", params: { agents: input.newAgents } }], signerAddress: o1.address });
  for (const [slot, w] of [[1, o1], [2, o2]]) {
    const env = await wr7.getOrCreateSlotSigningRequest({ config, requestId: op.id, slot });
    const sig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(op.transaction.unsignedSafeJson), op.rootInputIndex, w.key).slice(2, 2 + 130);
    await wr7.submitSlotSignature({ config, requestId: op.id, slot, response: { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: env.requestVersion, requestId: env.requestId, network: env.network, manifestHash: env.manifestHash, txId: env.txId, root: env.root, slot: env.slot, signerAddress: w.address, signatureHex: sig, sighashType: 1, signedAtMs: Date.now() } });
  }
  const opNow = await wr7.loadOrgRootRequest(config, op.id);
  const feeSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(op.transaction.unsignedSafeJson), opNow.build.frozen.inputs.length - 1, fee.key);
  const opSigned = await wr7.finalizeOrgRootRequest({ config, requestId: op.id, fuelSignatureScriptHex: feeSig });
  assert.equal(opSigned.state, "SIGNED");
  return { rootId, treasuryVaultId: tReq.vaultId, creationRequestId: gReq.requestId, creationVaultId: gReq.vaultId, rootRequestId: op.id };
}

/* ---------------- parent side ---------------- */
/* Write the RC44 KAS records in a child that loads only the overlay's RC44 modules; returns { dataRoot, result }. */
function runRc44Kas(input, { tree = process.env.POLICYVAULT_TEST_RC44_TREE || "", track = () => {} } = {}) {
  H44.verifyRc44Tree(tree);
  const dataRoot = H44.ownedTempRoot(`${H44.OWNED_PREFIX}r2-kas-rc44-data-`); track(dataRoot);
  const overlayRoot = H44.ownedTempRoot(`${H44.OWNED_PREFIX}r2-kas-rc44-overlay-`); track(overlayRoot);
  const overlay = H44.rc44Overlay(tree, overlayRoot);
  const env = { ...process.env }; delete env.POLICYVAULT_PV_VM_PREFLIGHT_PATH; delete env.POLICYVAULT_PV_CALL_ENCODER_PATH;
  const payload = JSON.stringify({ overlay, dataRoot, input });
  const r = require("node:child_process").spawnSync(process.execPath, [__filename, payload], { encoding: "utf8", timeout: 600000, maxBuffer: 64 * 1024 * 1024, env });
  assert.equal(r.status, 0, `RC44 KAS writer failed: ${(r.stderr || "").slice(-4000)}`);
  const line = (r.stdout || "").split("\n").find((l) => l.startsWith(RESULT_TAG));
  assert.ok(line, "the RC44 KAS writer reported its result");
  return { dataRoot, result: JSON.parse(line.slice(RESULT_TAG.length)) };
}

if (require.main === module) {
  child(JSON.parse(process.argv[2])).then(
    (result) => { process.stdout.write(`${RESULT_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = { runRc44Kas };
